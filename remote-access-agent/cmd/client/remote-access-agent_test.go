// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"
	"testing"

	"github.com/open-edge-platform/edge-node-agents/common/pkg/testutils"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/credentials"
)

func Test_envOrDefault(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		defValue string
		envValue string
		want     string
	}{
		{
			name:     "environment variable set",
			key:      "TEST_KEY",
			defValue: "default",
			envValue: "env_value",
			want:     "env_value",
		},
		{
			name:     "environment variable not set",
			key:      "TEST_KEY_NOT_SET",
			defValue: "default",
			envValue: "",
			want:     "default",
		},
		{
			name:     "environment variable set but empty",
			key:      "TEST_KEY_EMPTY",
			defValue: "default",
			envValue: "",
			want:     "default",
		},
		{
			name:     "environment variable set with whitespace",
			key:      "TEST_KEY_WHITESPACE",
			defValue: "default",
			envValue: "  ",
			want:     "default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envValue != "" {
				os.Setenv(tt.key, tt.envValue)
				defer os.Unsetenv(tt.key)
			} else {
				os.Unsetenv(tt.key)
			}

			got := envOrDefault(tt.key, tt.defValue)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_setLogLevel(t *testing.T) {
	// Save original level
	originalLevel := log.Logger.Level
	defer func() {
		log.Logger.SetLevel(originalLevel)
	}()

	tests := []struct {
		name     string
		logLevel string
		want     logrus.Level
	}{
		{
			name:     "debug level",
			logLevel: "debug",
			want:     logrus.DebugLevel,
		},
		{
			name:     "error level",
			logLevel: "error",
			want:     logrus.ErrorLevel,
		},
		{
			name:     "info level",
			logLevel: "info",
			want:     logrus.InfoLevel,
		},
		{
			name:     "case insensitive debug",
			logLevel: "DEBUG",
			want:     logrus.DebugLevel,
		},
		{
			name:     "case insensitive error",
			logLevel: "ERROR",
			want:     logrus.ErrorLevel,
		},
		{
			name:     "unknown level defaults to info",
			logLevel: "unknown",
			want:     logrus.InfoLevel,
		},
		{
			name:     "empty string defaults to info",
			logLevel: "",
			want:     logrus.InfoLevel,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setLogLevel(tt.logLevel)
			assert.Equal(t, tt.want, log.Logger.Level)
		})
	}
}

func Test_isCtxErr(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "context canceled",
			err:  context.Canceled,
			want: true,
		},
		{
			name: "context deadline exceeded",
			err:  context.DeadlineExceeded,
			want: true,
		},
		{
			name: "wrapped context canceled",
			err:  &customError{err: context.Canceled},
			want: true,
		},
		{
			name: "wrapped context deadline exceeded",
			err:  &customError{err: context.DeadlineExceeded},
			want: true,
		},
		{
			name: "other error",
			err:  assert.AnError,
			want: false,
		},
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isCtxErr(tt.err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// customError wraps an error to test error wrapping
type customError struct {
	err error
}

func (e *customError) Error() string {
	return e.err.Error()
}

func (e *customError) Unwrap() error {
	return e.err
}

func Test_buildTLSCreds(t *testing.T) {
	tests := []struct {
		name       string
		caPath     string
		serverName string
		wantErr    bool
		errMsg     string
		setup      func(t *testing.T) string
		cleanup    func(t *testing.T, path string)
	}{
		{
			name:       "certificate file not found",
			caPath:     "/nonexistent/path/ca.pem",
			serverName: "",
			wantErr:    true,
			errMsg:     "",
		},
		{
			name:       "invalid certificate file",
			caPath:     "",
			serverName: "",
			wantErr:    true,
			errMsg:     "bad CA pem",
			setup: func(t *testing.T) string {
				// Create a temporary file with invalid certificate content
				certFile, err := os.CreateTemp("", "test-ca-invalid-*.pem")
				require.NoError(t, err)
				defer certFile.Close()

				_, err = certFile.WriteString("invalid certificate content")
				require.NoError(t, err)
				return certFile.Name()
			},
			cleanup: func(t *testing.T, path string) {
				os.Remove(path)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caPath := tt.caPath
			if tt.setup != nil {
				caPath = tt.setup(t)
				if tt.cleanup != nil {
					defer tt.cleanup(t, caPath)
				}
			}

			creds, err := buildTLSCreds(caPath, tt.serverName)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
				assert.Nil(t, creds)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, creds)
				// Verify it's a TLS credentials type
				_, ok := creds.(credentials.TransportCredentials)
				assert.True(t, ok)
			}
		})
	}
}

func Test_buildTLSCreds_ValidCertificate(t *testing.T) {
	// Create a valid test certificate using testutils
	certContents, _, err := testutils.CreateCertificateAndKey()
	require.NoError(t, err)

	certFile, err := os.CreateTemp("", "test-ca-*.pem")
	require.NoError(t, err)
	defer os.Remove(certFile.Name())

	_, err = certFile.Write(certContents)
	require.NoError(t, err)
	certFile.Close()

	// Test with server name
	creds, err := buildTLSCreds(certFile.Name(), "test.example.com")
	require.NoError(t, err)
	assert.NotNil(t, creds)
	_, ok := creds.(credentials.TransportCredentials)
	assert.True(t, ok)

	// Test without server name
	creds2, err := buildTLSCreds(certFile.Name(), "")
	require.NoError(t, err)
	assert.NotNil(t, creds2)
	_, ok2 := creds2.(credentials.TransportCredentials)
	assert.True(t, ok2)
}
