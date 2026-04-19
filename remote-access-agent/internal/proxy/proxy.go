// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	chclient "github.com/jpillora/chisel/client"
	remaccessmgr "github.com/open-edge-platform/infra-managers/remote-access/pkg/api/rmtaccessmgr/v1"
)

type ChiselClient interface {
	Start(ctx context.Context) error
	Wait() error
	Run() error
	Close() error
}

type Factory func(cfg *chclient.Config) (ChiselClient, error)

func DefaultFactory(cfg *chclient.Config) (ChiselClient, error) {
	return chclient.NewClient(cfg)
}

type Connector struct {
	newClient Factory
}

func New(f Factory) *Connector { return &Connector{newClient: f} }

// StartConfig holds proxy configuration for fallback endpoint and edge-local Chisel target
type StartConfig struct {
	DefaultEndpoint string
	KeepAlive       time.Duration
	MaxRetryCount   int
	TargetHost      string
	TargetPort      uint32
}

// Start establishes a connection to the Chisel server on Remote Access Proxy.
// Endpoint from spec or defaultEndpoint may use wss:// / ws:// / https:// / http:// / bare host;
// values are normalized to https:// or http:// before chisel.Config.Server (see ensureEndpointScheme).
// According to Chisel documentation: https://github.com/jpillora/chisel
// - Client Config.Server must use http:// or https:// (library maps to ws/wss and TLS)
// - Reverse tunneling is supported with "R:" prefix in remotes
//
// onClientExit is invoked after the Chisel client errgroup finishes (same fingerprint, dead tunnel — agent-ram-poll-state-machine §6.1). May be nil (tests); production should pass a callback that clears tunnel state so the next ACTIVE poll can Start again.
//
// Call the returned runWatch exactly once after registering closeFn (e.g. tunnelmgr.SetTunnel) so a fast-failing client cannot clear state before the tunnel is tracked (§9.1).
func (c *Connector) Start(ctx context.Context, spec *remaccessmgr.AgentRemoteAccessSpec, cfg *StartConfig, onClientExit func()) (remoteAddr string, closeFn func() error, runWatch func(), err error) {
	targetHost := ""
	targetPort := uint32(0)
	if cfg != nil {
		targetHost = strings.TrimSpace(cfg.TargetHost)
		targetPort = cfg.TargetPort
	}
	if targetHost == "" || targetPort == 0 {
		return "", nil, nil, fmt.Errorf("proxy target host and port are required (from agent config)")
	}

	remoteDef := fmt.Sprintf(
		"R:%d:%s:%d", // reverse-bind:remotePort:targetHost:targetPort (Chisel reverse tunnel)
		spec.GetReverseBindPort(),
		targetHost,
		targetPort,
	)

	// Get endpoint from spec, fallback to config if empty
	endpoint := spec.GetRemoteAccessProxyEndpoint()
	if endpoint == "" && cfg != nil && cfg.DefaultEndpoint != "" {
		endpoint = cfg.DefaultEndpoint
	}
	if endpoint == "" {
		return "", nil, nil, fmt.Errorf("remote access proxy endpoint is required (from spec or config)")
	}

	// jpillora/chisel NewClient prepends "http://" unless Server already starts with "http";
	// values like "wss://host" become invalid combined URLs. Use https:// or http:// only.
	endpoint = ensureEndpointScheme(endpoint)

	keepAlive := 25 * time.Second
	maxRetry := -1
	if cfg != nil {
		if cfg.KeepAlive > 0 {
			keepAlive = cfg.KeepAlive
		}
		if cfg.MaxRetryCount != 0 {
			maxRetry = cfg.MaxRetryCount
		}
	}

	chiselCfg := &chclient.Config{
		Server:        endpoint,
		Auth:          spec.GetSessionToken(), // Session token for authentication (format: "user:pass")
		KeepAlive:     keepAlive,
		MaxRetryCount: maxRetry,
		Remotes:       []string{remoteDef},
		Verbose:       true,
	}
	cli, err := c.newClient(chiselCfg)
	if err != nil {
		return "", nil, nil, fmt.Errorf("chisel new client: %w", err)
	}

	if err := cli.Start(ctx); err != nil {
		_ = cli.Close()
		return "", nil, nil, fmt.Errorf("chisel start: %w", err)
	}

	// jpillora/chisel Start returns immediately; connection runs in an errgroup. Wait() unblocks
	// when the client stops (disconnect, Close, or unrecoverable error). defer Close ensures
	// cleanup if the owner never registers this client or Wait ends without going through closeFn.
	runWatch = func() {
		go func() {
			defer func() { _ = cli.Close() }()
			_ = cli.Wait()
			if onClientExit != nil {
				onClientExit()
			}
		}()
	}

	u, err := url.Parse(chiselCfg.Server)
	if err != nil {
		_ = cli.Close()
		return "", nil, nil, fmt.Errorf("bad proxy endpoint %q: %w", chiselCfg.Server, err)
	}
	// Return address for the reverse tunnel endpoint
	// ReverseBindPort is where the reverse tunnel will be accessible on the proxy side
	remoteAddr = net.JoinHostPort(u.Hostname(), strconv.Itoa(int(spec.GetReverseBindPort())))
	return remoteAddr, cli.Close, runWatch, nil
}

// ensureEndpointScheme returns a URL suitable for chisel.Config.Server (https:// or http://).
func ensureEndpointScheme(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return endpoint
	}

	switch {
	case strings.HasPrefix(endpoint, "wss://"):
		return "https://" + strings.TrimPrefix(endpoint, "wss://")
	case strings.HasPrefix(endpoint, "ws://"):
		return "http://" + strings.TrimPrefix(endpoint, "ws://")
	case strings.HasPrefix(endpoint, "https://"), strings.HasPrefix(endpoint, "http://"):
		return endpoint
	default:
		return "https://" + endpoint
	}
}
