// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

// Package logger provides centralized logging functionality for the Remote Access Agent
package logger

import (
	"github.com/open-edge-platform/edge-node-agents/common/pkg/logger"
	"github.com/open-edge-platform/edge-node-agents/remote-access-agent/info"
)

var Logger = logger.New(info.Component, info.Version)
