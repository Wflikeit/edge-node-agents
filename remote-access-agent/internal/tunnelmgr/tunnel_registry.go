// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

// Package tunnelmgr holds the agent's logical tunnel slot: the Chisel close callback
// registered after a successful Start plus the fingerprint of that spec. It does not dial
// or interpret RAM; cmd/client applies policy and calls SetTunnel / Close*.
//
// Single goroutine owns mutations in production (poll loop); the mutex serializes anyway.
package tunnelmgr

import (
	"sync"

	"github.com/sirupsen/logrus"
)

// CloseReason is logged when the tunnel is torn down (see agent-ram-poll-state-machine.md §11).
type CloseReason string

const (
	// CloseReasonNone is RAM CONFIG_STATUS_NONE (no RAC for host), not “no reason / noop”.
	CloseReasonNone                CloseReason = "CLOSE_NONE"
	CloseReasonPending             CloseReason = "CLOSE_PENDING"
	CloseReasonDisabled            CloseReason = "CLOSE_DISABLED"
	CloseReasonError               CloseReason = "CLOSE_ERROR"
	CloseReasonExpiredLocal        CloseReason = "CLOSE_EXPIRED_LOCAL"
	CloseReasonContractActiveNil   CloseReason = "CLOSE_CONTRACT_ACTIVE_NIL_SPEC"
	CloseReasonContractUnspecified CloseReason = "CLOSE_CONTRACT_UNSPECIFIED"
	CloseReasonFingerprintChanged  CloseReason = "CLOSE_FINGERPRINT_CHANGED"
	CloseReasonFingerprintInvalid  CloseReason = "CLOSE_FINGERPRINT_INVALID"
	CloseReasonTunnelDead          CloseReason = "CLOSE_TUNNEL_DEAD"
	CloseReasonRPCStale            CloseReason = "CLOSE_RPC_STALE"
	CloseReasonShutdown            CloseReason = "CLOSE_SHUTDOWN"
	CloseReasonUnexpectedStatus    CloseReason = "CLOSE_UNEXPECTED_STATUS"
)

// Registry holds one logical tunnel registration: closeFn from the live Chisel client and
// the fingerprint of the spec used at SetTunnel. HasTunnel does not imply TCP is healthy—only
// that we have not yet cleared this registration (see proxy liveness / §6.1).
type Registry struct {
	mu sync.Mutex

	log *logrus.Logger

	closeFn         func() error
	lastFingerprint string
}

// New returns a registry for the process single tunnel slot. log may be nil (no close logs).
func New(log *logrus.Logger) *Registry {
	return &Registry{log: log}
}

// HasTunnel reports whether closeFn is set (poll logic has a tunnel slot to close or to compare fingerprints against).
func (r *Registry) HasTunnel() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closeFn != nil
}

// LastFingerprint is the fingerprint passed to SetTunnel for the current registration; cleared whenever
// the tunnel is torn down. Used only while HasTunnel is true to detect spec rotation (new Start).
func (r *Registry) LastFingerprint() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastFingerprint
}

// CloseIfOpen invokes the Chisel close callback when registered, clears registration, and returns
// true; if already idle returns false (no callback, no Info log—e.g. Chisel onExit after teardown).
func (r *Registry) CloseIfOpen(reason CloseReason) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closeFn == nil {
		return false
	}
	r.closeBestEffortLocked(reason)
	return true
}

// CloseBestEffort is like CloseIfOpen but allowed when already idle (e.g. defer shutdown); no “did work” bool.
func (r *Registry) CloseBestEffort(reason CloseReason) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closeBestEffortLocked(reason)
}

func (r *Registry) closeBestEffortLocked(reason CloseReason) {
	fn := r.closeFn
	r.closeFn = nil
	r.lastFingerprint = ""
	if fn == nil {
		return
	}
	if err := fn(); err != nil && r.log != nil {
		r.log.Warnf("tunnel close (%s): %v (logical state cleared anyway)", reason, err)
	} else if r.log != nil {
		r.log.Infof("tunnel closed (%s)", reason)
	}
}

// SetTunnel binds this process’s single tunnel slot after Connector.Start returns; caller must not
// register nil closeFn. fingerprint should match the spec used for that Start (caller validates).
func (r *Registry) SetTunnel(closeFn func() error, fingerprint string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closeFn = closeFn
	r.lastFingerprint = fingerprint
}
