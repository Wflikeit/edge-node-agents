// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

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

