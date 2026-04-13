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
		TargetHost:                "127.0.0.1",
		TargetPort:                22,
	}
	b := &remaccessmgr.AgentRemoteAccessSpec{
		RemoteAccessProxyEndpoint: "", // fallback to default
		SessionToken:              "u:p",
		ReverseBindPort:           21001,
		TargetHost:                "127.0.0.1",
		TargetPort:                22,
	}
	fa, err := SpecChiselFingerprint(a, def)
	require.NoError(t, err)
	fb, err := SpecChiselFingerprint(b, def)
	require.NoError(t, err)
	require.Equal(t, fa, fb)
}

func TestSpecChiselFingerprint_differsOnToken(t *testing.T) {
	def := "wss://h:1"
	base := &remaccessmgr.AgentRemoteAccessSpec{
		RemoteAccessProxyEndpoint: def,
		SessionToken:              "a:b",
		ReverseBindPort:           1,
		TargetHost:                "127.0.0.1",
		TargetPort:                22,
	}
	other := &remaccessmgr.AgentRemoteAccessSpec{
		RemoteAccessProxyEndpoint: def,
		SessionToken:              "a:c",
		ReverseBindPort:           1,
		TargetHost:                "127.0.0.1",
		TargetPort:                22,
	}
	fa, err := SpecChiselFingerprint(base, "")
	require.NoError(t, err)
	fb, err := SpecChiselFingerprint(other, "")
	require.NoError(t, err)
	require.NotEqual(t, fa, fb)
}
