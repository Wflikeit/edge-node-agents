// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

// Package logger provides centralized logging functionality for the Remote Access Agent
package logger

import (
	"github.com/open-edge-platform/edge-node-agents/common/pkg/logger"
)

const (
	Component = "Remote Access Agent"
	Version   = "1.0.0-dev" // TODO: inject version at build time
)

var Logger = logger.New(Component, Version)
