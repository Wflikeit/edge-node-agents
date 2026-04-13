// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package tunnelmgr

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCloseIfOpen_idleReturnsFalse(t *testing.T) {
	r := New(nil)
	ok := r.CloseIfOpen(CloseReasonNone)
	require.False(t, ok)
}

func TestCloseIfOpen_closesAndReturnsTrue(t *testing.T) {
	r := New(nil)
	var closed bool
	r.SetTunnel(func() error {
		closed = true
		return nil
	}, "fp")
	ok := r.CloseIfOpen(CloseReasonError)
	require.True(t, ok)
	require.True(t, closed)
	require.False(t, r.HasTunnel())
}

func TestCloseIfOpen_idempotentSecondCall(t *testing.T) {
	r := New(nil)
	r.SetTunnel(func() error { return errors.New("x") }, "fp")
	require.True(t, r.CloseIfOpen(CloseReasonPending))
	require.False(t, r.CloseIfOpen(CloseReasonPending))
}
