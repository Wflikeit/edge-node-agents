// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package tenantjwt

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// JWT (alg none): {"realm_access":{"roles":["11111111-1111-1111-1111-111111111111_admin","offline_access"]}}
const testJWT = "eyJhbGciOiJub25lIn0.eyJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsiMTExMTExMTEtMTExMS0xMTExLTExMTEtMTExMTExMTExMTExX2FkbWluIiwib2ZmbGluZV9hY2Nlc3MiXX19.e30"

func TestTenantIDFromJWT(t *testing.T) {
	id, err := TenantIDFromJWT(testJWT)
	require.NoError(t, err)
	require.Equal(t, "11111111-1111-1111-1111-111111111111", id)
}

func TestFromAccessTokenFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "access_token")
	require.NoError(t, os.WriteFile(p, []byte(testJWT+"\n"), 0o600))
	id, err := FromAccessTokenFile(p)
	require.NoError(t, err)
	require.Equal(t, "11111111-1111-1111-1111-111111111111", id)
}
