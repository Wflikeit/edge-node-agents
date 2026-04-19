// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"fmt"
	"strings"

	remaccessmgr "github.com/open-edge-platform/infra-managers/remote-access/pkg/api/rmtaccessmgr/v1"
)

// SpecChiselFingerprint returns a canonical string identity of the fields that
// Connector.Start passes to Chisel (endpoint resolution, auth, reverse remote).
// Same fingerprint => same Chisel inputs after normalization; different => reconfigure tunnel.
// localTargetHost and localTargetPort come from agent config (not RAM).
func SpecChiselFingerprint(spec *remaccessmgr.AgentRemoteAccessSpec, defaultEndpoint string, localTargetHost string, localTargetPort uint32) (string, error) {
	if spec == nil {
		return "", fmt.Errorf("nil spec")
	}
	endpoint := strings.TrimSpace(spec.GetRemoteAccessProxyEndpoint())
	if endpoint == "" {
		endpoint = strings.TrimSpace(defaultEndpoint)
	}
	if endpoint == "" {
		return "", fmt.Errorf("remote access proxy endpoint is required (from spec or config)")
	}
	endpoint = ensureEndpointScheme(endpoint)

	sessionTok := strings.TrimSpace(spec.GetSessionToken())
	targetHost := strings.TrimSpace(localTargetHost)
	if targetHost == "" || localTargetPort == 0 {
		return "", fmt.Errorf("proxy target host and port are required (from agent config)")
	}
	// Record separator avoids accidental merges between fields.
	const sep = "\x1e"
	return strings.Join([]string{
		endpoint,
		sessionTok,
		fmt.Sprintf("%d", spec.GetReverseBindPort()),
		targetHost,
		fmt.Sprintf("%d", localTargetPort),
	}, sep), nil
}
