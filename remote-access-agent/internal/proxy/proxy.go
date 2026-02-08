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

// StartConfig holds proxy configuration for fallback endpoint
type StartConfig struct {
	DefaultEndpoint string
	KeepAlive       time.Duration
	MaxRetryCount   int
}

// Start establishes a connection to the Chisel server on Remote Access Proxy.
// The endpoint URL should be in format: wss://host:port (for WebSocket Secure via Traefik)
// or ws://host:port (for plain WebSocket). If spec doesn't provide endpoint,
// defaultEndpoint from config is used as fallback.
// According to Chisel documentation: https://github.com/jpillora/chisel
// - Chisel uses WebSocket transport (ws:// or wss://)
// - Through Traefik reverse proxy, connections are secured with TLS (wss://)
// - Reverse tunneling is supported with "R:" prefix in remotes
func (c *Connector) Start(ctx context.Context, spec *remaccessmgr.AgentRemoteAccessSpec, cfg *StartConfig) (remoteAddr string, closeFn func() error, err error) {
	remoteDef := fmt.Sprintf(
		"R:%d:%s:%d", // reverse-bind:remotePort:targetHost:targetPort (Chisel reverse tunnel)
		spec.GetReverseBindPort(),
		spec.GetTargetHost(),
		spec.GetTargetPort(),
	)

	// Get endpoint from spec, fallback to config if empty
	endpoint := spec.GetRemoteAccessProxyEndpoint()
	if endpoint == "" && cfg != nil && cfg.DefaultEndpoint != "" {
		endpoint = cfg.DefaultEndpoint
	}
	if endpoint == "" {
		return "", nil, fmt.Errorf("remote access proxy endpoint is required (from spec or config)")
	}

	// Ensure endpoint has a scheme (wss:// or ws://)
	// Chisel supports http/https/ws/wss, but through Traefik we use wss://
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
		return "", nil, fmt.Errorf("chisel new client: %w", err)
	}

	if err := cli.Start(ctx); err != nil {
		_ = cli.Close()
		return "", nil, fmt.Errorf("chisel start: %w", err)
	}

	u, err := url.Parse(chiselCfg.Server)
	if err != nil {
		_ = cli.Close()
		return "", nil, fmt.Errorf("bad proxy endpoint %q: %w", chiselCfg.Server, err)
	}
	// Return address for the reverse tunnel endpoint
	// ReverseBindPort is where the reverse tunnel will be accessible on the proxy side
	remoteAddr = net.JoinHostPort(u.Hostname(), strconv.Itoa(int(spec.GetReverseBindPort())))
	return remoteAddr, cli.Close, nil
}

// ensureEndpointScheme ensures the endpoint URL has a proper scheme.
// If no scheme is provided, defaults to wss:// (WebSocket Secure) which is used through Traefik.
func ensureEndpointScheme(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return endpoint
	}

	// Check if already has a scheme
	if strings.HasPrefix(endpoint, "ws://") ||
		strings.HasPrefix(endpoint, "wss://") ||
		strings.HasPrefix(endpoint, "http://") ||
		strings.HasPrefix(endpoint, "https://") {
		return endpoint
	}

	// Default to wss:// for secure connections through Traefik
	// Chisel uses WebSocket, and through Traefik it's secured with TLS (WSS)
	return "wss://" + endpoint
}
