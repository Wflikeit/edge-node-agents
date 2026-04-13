// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	remaccessmgr "github.com/open-edge-platform/infra-managers/remote-access/pkg/api/rmtaccessmgr/v1"
	chclient "github.com/jpillora/chisel/client"
	"github.com/stretchr/testify/require"
)

type fakeChisel struct {
	startErr error
	waitErr  error
	unblock  chan struct{}

	closed atomic.Bool
}

func (f *fakeChisel) Start(ctx context.Context) error { return f.startErr }

func (f *fakeChisel) Wait() error {
	if f.unblock != nil {
		<-f.unblock
	}
	return f.waitErr
}

func (f *fakeChisel) Close() error {
	f.closed.Store(true)
	return nil
}

func (f *fakeChisel) Run() error { return nil }

func TestConnector_Start_runWatchAfterRegister_invokesOnExit(t *testing.T) {
	unblock := make(chan struct{})
	fake := &fakeChisel{unblock: unblock}
	conn := New(func(cfg *chclient.Config) (ChiselClient, error) { return fake, nil })

	var exitCount atomic.Int32
	spec := &remaccessmgr.AgentRemoteAccessSpec{
		RemoteAccessProxyEndpoint: "wss://example.test:443",
		SessionToken:              "u:p",
		ReverseBindPort:           1,
		TargetHost:                "127.0.0.1",
		TargetPort:                22,
	}
	_, closeFn, runWatch, err := conn.Start(context.Background(), spec, &StartConfig{}, func() {
		exitCount.Add(1)
	})
	require.NoError(t, err)
	require.NotNil(t, closeFn)
	require.NotNil(t, runWatch)

	runWatch()
	close(unblock)

	require.Eventually(t, func() bool { return exitCount.Load() == 1 }, 2*time.Second, 10*time.Millisecond)
}

func TestEnsureEndpointScheme(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"", ""},
		{"  ", ""},
		{"wss://proxy.example:443/path", "https://proxy.example:443/path"},
		{"ws://proxy.example:80", "http://proxy.example:80"},
		{"https://proxy.example:443", "https://proxy.example:443"},
		{"http://proxy.example:8080", "http://proxy.example:8080"},
		{"proxy.internal:443", "https://proxy.internal:443"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			require.Equal(t, tt.want, ensureEndpointScheme(tt.in))
		})
	}
}

func TestConnector_Start_propagatesStartError(t *testing.T) {
	fake := &fakeChisel{startErr: context.Canceled}
	conn := New(func(cfg *chclient.Config) (ChiselClient, error) { return fake, nil })
	spec := &remaccessmgr.AgentRemoteAccessSpec{
		RemoteAccessProxyEndpoint: "wss://example.test:443",
		SessionToken:              "u:p",
		ReverseBindPort:           1,
		TargetHost:                "127.0.0.1",
		TargetPort:                22,
	}
	_, _, runWatch, err := conn.Start(context.Background(), spec, &StartConfig{}, nil)
	require.Error(t, err)
	require.Nil(t, runWatch)
}
