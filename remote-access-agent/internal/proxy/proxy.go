// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
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

func (c *Connector) Start(ctx context.Context, spec *remaccessmgr.AgentRemoteAccessSpec) (remoteAddr string, closeFn func() error, err error) {

	remoteDef := fmt.Sprintf(
		"R:%d:%s:%d", // reverse-bind:remotePort:targetHost:targetPort
		spec.GetReverseBindPort(),
		spec.GetTargetHost(),
		spec.GetTargetPort(),
	)

	cfg := &chclient.Config{
		Server:        spec.GetRemoteAccessProxyEndpoint(),
		Auth:          spec.GetSessionToken(), // e.g. "admin:secret"
		KeepAlive:     25 * time.Second,
		MaxRetryCount: -1, // infinite retry
		Remotes:       []string{remoteDef},
		Verbose:       true,
	}
	cli, err := c.newClient(cfg)
	if err != nil {
		return "", nil, fmt.Errorf("chisel new client: %w", err)
	}

	if err := cli.Start(ctx); err != nil {
		_ = cli.Close()
		return "", nil, fmt.Errorf("chisel start: %w", err)
	}

	u, err := url.Parse(cfg.Server)
	if err != nil {
		_ = cli.Close()
		return "", nil, fmt.Errorf("bad proxy endpoint %q: %w", cfg.Server, err)
	}
	remoteAddr = net.JoinHostPort(u.Hostname(), strconv.Itoa(8080))
	return remoteAddr, cli.Close, nil
}
