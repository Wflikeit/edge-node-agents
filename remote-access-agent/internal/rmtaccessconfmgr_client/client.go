// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package grpcclient

import (
	"context"
	"errors"
	"fmt"
	"time"

	remaccessmgrv1 "github.com/open-edge-platform/infra-managers/remote-access/pkg/api/rmtaccessmgr/v1"
	"google.golang.org/grpc"
	gbackoff "google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

// RAClient is the minimal interface used by the edge agent.
// It only needs to read Remote Access specs from the Manager service.
type RAClient interface {
	// GetRemoteAccessConfig calls RAM GetRemoteAccessConfigByGuid. On success, err is nil and the
	// caller must inspect ConfigStatus (NONE/PENDING/ACTIVE/…) — nil spec is valid for NONE/PENDING/DISABLED.
	// Tenant is derived server-side from the gRPC metadata Bearer JWT (see utils.GetAuthContext).
	GetRemoteAccessConfig(ctx context.Context, hostUUID string) (*remaccessmgrv1.GetResourceAccessConfigResponse, error)
}

type client struct {
	conn *grpc.ClientConn
	stub remaccessmgrv1.RmtaccessmgrServiceClient
}

// New establishes a blocking gRPC connection to ResourceAccessManagerService.
// `creds` may be nil in dev/local; insecure credentials will be used then.
func New(ctx context.Context, addr string, creds credentials.TransportCredentials) (RAClient, func() error, error) {
	if creds == nil {
		creds = insecure.NewCredentials() // dev/local only
	}

	cc, err := grpc.DialContext(
		ctx,
		addr,
		grpc.WithTransportCredentials(creds),
		grpc.WithBlock(), // block until the initial connection is established (or ctx times out)
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff: gbackoff.Config{
				BaseDelay:  100 * time.Millisecond,
				Multiplier: 1.6,
				Jitter:     0.2,
				MaxDelay:   3 * time.Second,
			},
			MinConnectTimeout: 3 * time.Second,
		}),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                120 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: false,
		}),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("gRPC dial %q: %w", addr, err)
	}

	cleanup := func() error { return cc.Close() }

	return &client{
		conn: cc,
		stub: remaccessmgrv1.NewRmtaccessmgrServiceClient(cc),
	}, cleanup, nil
}

// GetRemoteAccessConfig fetches the full polling response for the host SMBIOS UUID.
func (c *client) GetRemoteAccessConfig(ctx context.Context, hostUUID string) (*remaccessmgrv1.GetResourceAccessConfigResponse, error) {
	if hostUUID == "" {
		return nil, errors.New("host uuid must not be empty")
	}

	rpcCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	resp, err := c.stub.GetRemoteAccessConfigByGuid(rpcCtx, &remaccessmgrv1.GetRemoteAccessConfigByGuidRequest{Uuid: hostUUID})
	if err != nil {
		return nil, fmt.Errorf("GetRemoteAccessConfigByGuid: %w", err)
	}
	return resp, nil
}
