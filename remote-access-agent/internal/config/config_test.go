// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"os"
	"testing"
	"time"

	"github.com/open-edge-platform/edge-node-agents/remote-access-agent/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

const (
	testGUID            = "123e4567-e89b-12d3-a456-426614174000"
	testLogLevel        = "info"
	testServiceURL      = "localhost:50051"
	testAccessTokenPath = "/etc/intel_edge_node/tokens/remote-access-agent/access_token" // #nosec G101
	testProxyEndpoint   = "wss://remote-access-proxy-ws.domain"
	testMetricsEndpoint = "unix:///run/platform-observability-agent/platform-observability-agent.sock"
	testStatusEndpoint  = "unix:///run/node-agent/node-agent.sock"
)

// createConfigFile creates a temporary YAML config file for testing
func createConfigFile(t *testing.T, guid, serviceURL, accessTokenPath string, proxyEndpoint string) string {
	f, err := os.CreateTemp("", "test_config")
	require.NoError(t, err)
	defer f.Close()

	newConfig := config.Config{
		Version:  "v0.0.1",
		LogLevel: testLogLevel,
		GUID:     guid,
		RemoteAccessManager: config.RemoteAccessManagerConfig{
			ServiceURL: serviceURL,
		},
		Proxy: config.ProxyConfig{
			DefaultEndpoint: proxyEndpoint,
		},
		JWT: config.JWTConfig{
			AccessTokenPath: accessTokenPath,
		},
		MetricsEndpoint: testMetricsEndpoint,
		MetricsInterval: 10 * time.Second,
		StatusEndpoint:  testStatusEndpoint,
	}

	file, err := yaml.Marshal(newConfig)
	require.NoError(t, err)

	_, err = f.Write(file)
	require.NoError(t, err)

	err = f.Close()
	require.NoError(t, err)
	return f.Name()
}

// createMinimalConfigFile creates a minimal valid config file
func createMinimalConfigFile(t *testing.T) string {
	return createConfigFile(t, testGUID, testServiceURL, testAccessTokenPath, "")
}

// Test_New_ValidConfig tests loading a valid configuration file
func Test_New_ValidConfig(t *testing.T) {
	fileName := createMinimalConfigFile(t)
	defer os.Remove(fileName)

	cfg, err := config.New(fileName)

	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, testGUID, cfg.GUID)
	assert.Equal(t, testLogLevel, cfg.LogLevel)
	assert.Equal(t, testServiceURL, cfg.RemoteAccessManager.ServiceURL)
	assert.Equal(t, testAccessTokenPath, cfg.JWT.AccessTokenPath)
}

// Test_New_AllFields tests that all fields are correctly loaded from config
func Test_New_AllFields(t *testing.T) {
	fileName := createConfigFile(t, testGUID, testServiceURL, testAccessTokenPath, testProxyEndpoint)
	defer os.Remove(fileName)

	cfg, err := config.New(fileName)

	require.NoError(t, err)
	assert.Equal(t, "v0.0.1", cfg.Version)
	assert.Equal(t, testLogLevel, cfg.LogLevel)
	assert.Equal(t, testGUID, cfg.GUID)
	assert.Equal(t, testServiceURL, cfg.RemoteAccessManager.ServiceURL)
	assert.Equal(t, testProxyEndpoint, cfg.Proxy.DefaultEndpoint)
	assert.Equal(t, testAccessTokenPath, cfg.JWT.AccessTokenPath)
	assert.Equal(t, testMetricsEndpoint, cfg.MetricsEndpoint)
	assert.Equal(t, 10*time.Second, cfg.MetricsInterval)
	assert.Equal(t, testStatusEndpoint, cfg.StatusEndpoint)
}

// Test_New_Defaults tests that default values are set correctly
func Test_New_Defaults(t *testing.T) {
	fileName := createMinimalConfigFile(t)
	defer os.Remove(fileName)

	cfg, err := config.New(fileName)

	require.NoError(t, err)
	// Check default proxy values
	assert.Equal(t, 25*time.Second, cfg.Proxy.Keepalive)
	assert.Equal(t, -1, cfg.Proxy.MaxRetry) // infinite retry

	// Check default metrics interval
	assert.Equal(t, 10*time.Second, cfg.MetricsInterval)
}

// Test_New_CustomDefaults tests that custom values override defaults
func Test_New_CustomDefaults(t *testing.T) {
	f, err := os.CreateTemp("", "test_config")
	require.NoError(t, err)
	defer f.Close()

	customConfig := config.Config{
		Version:  "v0.0.1",
		LogLevel: testLogLevel,
		GUID:     testGUID,
		RemoteAccessManager: config.RemoteAccessManagerConfig{
			ServiceURL: testServiceURL,
		},
		Proxy: config.ProxyConfig{
			Keepalive: 30 * time.Second,
			MaxRetry:  10,
		},
		JWT: config.JWTConfig{
			AccessTokenPath: testAccessTokenPath,
		},
		MetricsInterval: 20 * time.Second,
	}

	file, err := yaml.Marshal(customConfig)
	require.NoError(t, err)

	_, err = f.Write(file)
	require.NoError(t, err)

	err = f.Close()
	require.NoError(t, err)

	cfg, err := config.New(f.Name())
	defer os.Remove(f.Name())

	require.NoError(t, err)
	// Custom values should be preserved
	assert.Equal(t, 30*time.Second, cfg.Proxy.Keepalive)
	assert.Equal(t, 10, cfg.Proxy.MaxRetry)
	assert.Equal(t, 20*time.Second, cfg.MetricsInterval)
}

// Test_New_EmptyPath tests that empty config path returns error
func Test_New_EmptyPath(t *testing.T) {
	cfg, err := config.New("")

	assert.Error(t, err)
	assert.Nil(t, cfg)
	assert.Contains(t, err.Error(), "config file path is required")
}

// Test_New_FileNotExists tests that non-existent file returns error
func Test_New_FileNotExists(t *testing.T) {
	cfg, err := config.New("/non/existent/path/config.yaml")

	assert.Error(t, err)
	assert.Nil(t, cfg)
	assert.Contains(t, err.Error(), "failed to read config file")
}

// Test_New_InvalidYAML tests that invalid YAML returns error
func Test_New_InvalidYAML(t *testing.T) {
	f, err := os.CreateTemp("", "test_config")
	require.NoError(t, err)
	defer f.Close()

	_, err = f.WriteString("this is not valid YAML: [")
	require.NoError(t, err)

	err = f.Close()
	require.NoError(t, err)

	cfg, err := config.New(f.Name())
	defer os.Remove(f.Name())

	assert.Error(t, err)
	assert.Nil(t, cfg)
	assert.Contains(t, err.Error(), "failed to parse config file")
}

// Test_New_MissingGUID tests that missing GUID returns error
func Test_New_MissingGUID(t *testing.T) {
	fileName := createConfigFile(t, "", testServiceURL, testAccessTokenPath, "")
	defer os.Remove(fileName)

	cfg, err := config.New(fileName)

	assert.Error(t, err)
	assert.Nil(t, cfg)
	assert.Contains(t, err.Error(), "GUID is required")
}

// Test_New_MissingServiceURL tests that missing service URL returns error
func Test_New_MissingServiceURL(t *testing.T) {
	fileName := createConfigFile(t, testGUID, "", testAccessTokenPath, "")
	defer os.Remove(fileName)

	cfg, err := config.New(fileName)

	assert.Error(t, err)
	assert.Nil(t, cfg)
	assert.Contains(t, err.Error(), "remoteAccessManager.serviceURL is required")
}

// Test_New_MissingServiceURL tests that missing service URL returns error
func Test_New_MissingProxyDefaultEndpoint(t *testing.T) {
	fileName := createConfigFile(t, testGUID, testServiceURL, testAccessTokenPath, "")
	defer os.Remove(fileName)

	cfg, err := config.New(fileName)

	assert.Error(t, err)
	assert.Nil(t, cfg)
	assert.Contains(t, err.Error(), "Proxy.DefaultEndpoint is required")
}

// Test_New_MissingAccessTokenPath tests that missing access token path returns error
func Test_New_MissingAccessTokenPath(t *testing.T) {
	fileName := createConfigFile(t, testGUID, testServiceURL, "", "")
	defer os.Remove(fileName)

	cfg, err := config.New(fileName)

	assert.Error(t, err)
	assert.Nil(t, cfg)
	assert.Contains(t, err.Error(), "jwt.accessTokenPath is required")
}

// Test_New_Symlink tests that symlink files are rejected
func Test_New_Symlink(t *testing.T) {
	// Create a regular file
	regularFile, err := os.CreateTemp("", "regular_file")
	require.NoError(t, err)
	defer regularFile.Close()

	// Write minimal valid config
	minimalConfig := config.Config{
		GUID: testGUID,
		RemoteAccessManager: config.RemoteAccessManagerConfig{
			ServiceURL: testServiceURL,
		},
		JWT: config.JWTConfig{
			AccessTokenPath: testAccessTokenPath,
		},
	}
	file, err := yaml.Marshal(minimalConfig)
	require.NoError(t, err)
	_, err = regularFile.Write(file)
	require.NoError(t, err)
	regularFile.Close()

	// Create symlink
	symlinkPath := "/tmp/symlink_ra_config.yaml"
	defer os.Remove(symlinkPath)
	err = os.Symlink(regularFile.Name(), symlinkPath)
	require.NoError(t, err)
	defer os.Remove(regularFile.Name())

	cfg, err := config.New(symlinkPath)

	assert.Error(t, err)
	assert.Nil(t, cfg)
	// ReadFileNoLinks should reject symlinks
	assert.Contains(t, err.Error(), "failed to read config file")
}
