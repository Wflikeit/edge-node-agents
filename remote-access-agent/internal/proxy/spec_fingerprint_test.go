// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"testing"

	remaccessmgr "github.com/open-edge-platform/infra-managers/remote-access/pkg/api/rmtaccessmgr/v1"
	"github.com/stretchr/testify/require"
)

func TestSpecChiselFingerprint_sameAfterNormalization(t *testing.T) {
	def := "proxy.example:443"
	a := &remaccessmgr.AgentRemoteAccessSpec{
		RemoteAccessProxyEndpoint: "proxy.example:443",
		SessionToken:              "u:p",
		ReverseBindPort:           21001,
	}
	b := &remaccessmgr.AgentRemoteAccessSpec{
		RemoteAccessProxyEndpoint: "", // fallback to default
		SessionToken:              "u:p",
		ReverseBindPort:           21001,
	}
	const localHost = "127.0.0.1"
	const localPort = uint32(22)
	fa, err := SpecChiselFingerprint(a, def, localHost, localPort)
	require.NoError(t, err)
	fb, err := SpecChiselFingerprint(b, def, localHost, localPort)
	require.NoError(t, err)
	require.Equal(t, fa, fb)
}

func TestSpecChiselFingerprint_differsOnToken(t *testing.T) {
	def := "wss://h:1"
	base := &remaccessmgr.AgentRemoteAccessSpec{
		RemoteAccessProxyEndpoint: def,
		SessionToken:              "a:b",
		ReverseBindPort:           1,
	}
	other := &remaccessmgr.AgentRemoteAccessSpec{
		RemoteAccessProxyEndpoint: def,
		SessionToken:              "a:c",
		ReverseBindPort:           1,
	}
	fa, err := SpecChiselFingerprint(base, "", "127.0.0.1", 22)
	require.NoError(t, err)
	fb, err := SpecChiselFingerprint(other, "", "127.0.0.1", 22)
	require.NoError(t, err)
	require.NotEqual(t, fa, fb)
}
