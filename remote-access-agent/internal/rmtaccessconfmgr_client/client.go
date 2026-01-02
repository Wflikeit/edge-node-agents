package grpcclient

import (
	"context"
	"errors"
	"fmt"
	"time"

	remaccessmgrv1 "github.com/open-edge-platform/infra-managers/remote-access/pkg/api/remaccessmgr/v1"
	"google.golang.org/grpc"
	gbackoff "google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

// RAClient is the minimal interface used by the edge agent.
// It only needs to read Remote Access specs from the Manager service.
type RAClient interface {
	// GetSpecByUUID fetches the agent's Remote Access configuration by RA UUID.
	GetSpecByUUID(ctx context.Context, uuid string) (*remaccessmgrv1.AgentRemoteAccessSpec, error)
}

type client struct {
	conn *grpc.ClientConn
	stub remaccessmgrv1.RemaccessmgrServiceClient
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
		stub: remaccessmgrv1.NewRemaccessmgrServiceClient(cc),
	}, cleanup, nil
}

// GetSpecByUUID fetches the agent configuration (spec) for the given Remote Access UUID.
func (c *client) GetSpecByUUID(ctx context.Context, uuid string) (*remaccessmgrv1.AgentRemoteAccessSpec, error) {
	if uuid == "" {
		return nil, errors.New("uuid must not be empty")
	}

	// Short per-RPC deadline to avoid hanging the agent
	rpcCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	resp, err := c.stub.GetRemoteAccessConfigByGuid(rpcCtx, &remaccessmgrv1.GetRemoteAccessConfigByGuidRequest{Uuid: uuid})
	if err != nil {
		return nil, fmt.Errorf("GetAgentSpec RPC failed: %w", err)
	}
	spec := resp.GetSpec()
	if spec == nil {
		return nil, errors.New("GetAgentSpec returned nil spec")
	}
	return spec, nil
}
