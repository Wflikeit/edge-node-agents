// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

// Package tenantjwt extracts tenant UUID from Keycloak-style JWTs (realm_access.roles).
package tenantjwt

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/open-edge-platform/edge-node-agents/common/pkg/utils"
)

const tenantIDRoleSeparator = "_"

var uuidRegex = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

type tokenClaims struct {
	jwt.RegisteredClaims
	RealmAccess realmAccess `json:"realm_access"`
}

type realmAccess struct {
	Roles []string `json:"roles"`
}

// FromAccessTokenFile reads the JWT from path and returns the tenant UUID derived from
// realm_access.roles entries shaped as "{tenantUUID}_<suffix>" (same rules as edge onboarding).
func FromAccessTokenFile(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("access token path is empty")
	}
	raw, err := utils.ReadFileNoLinks(path)
	if err != nil {
		return "", fmt.Errorf("read access token: %w", err)
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", fmt.Errorf("access token file is empty")
	}
	return TenantIDFromJWT(token)
}

// TenantIDFromJWT parses the token without signature verification and extracts the tenant UUID.
func TenantIDFromJWT(token string) (string, error) {
	parser := jwt.Parser{}
	t, _, err := parser.ParseUnverified(token, &tokenClaims{})
	if err != nil {
		return "", fmt.Errorf("parse jwt: %w", err)
	}
	claims, ok := t.Claims.(*tokenClaims)
	if !ok {
		return "", fmt.Errorf("unexpected jwt claims type")
	}
	var tenantIDs []string
	for _, role := range claims.RealmAccess.Roles {
		if !strings.Contains(role, tenantIDRoleSeparator) {
			continue
		}
		roleTID := strings.Split(role, tenantIDRoleSeparator)[0]
		if !uuidRegex.MatchString(roleTID) {
			continue
		}
		if !slices.Contains(tenantIDs, roleTID) {
			tenantIDs = append(tenantIDs, roleTID)
		}
	}
	if len(tenantIDs) == 0 {
		return "", fmt.Errorf("no tenant ID found in JWT realm_access.roles")
	}
	if len(tenantIDs) > 1 {
		return "", fmt.Errorf("multiple tenant IDs in JWT: %v", tenantIDs)
	}
	return tenantIDs[0], nil
}
