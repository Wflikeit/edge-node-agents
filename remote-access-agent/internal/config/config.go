// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

// Package config contains Remote Access Agent configuration management
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/open-edge-platform/edge-node-agents/common/pkg/utils"
	yaml "gopkg.in/yaml.v3"
)

// RemoteAccessManagerConfig contains Remote Access Manager service configuration
type RemoteAccessManagerConfig struct {
	ServiceURL   string        `yaml:"serviceURL"`             // gRPC service address
	PollInterval time.Duration `yaml:"pollInterval,omitempty"` // delay between GetRemoteAccessConfig polls
}

// ProxyConfig contains proxy configuration
type ProxyConfig struct {
	Keepalive       time.Duration `yaml:"keepalive"`
	MaxRetry        int           `yaml:"max_retry"`
	DefaultEndpoint string        `yaml:"defaultEndpoint,omitempty"`
	// TargetHost is the edge-local address Chisel forwards tunneled traffic to (e.g. loopback SSH).
	TargetHost string `yaml:"targetHost,omitempty"`
	// TargetPort is the edge-local port (e.g. 22 for SSH). Not sourced from RAM/inventory.
	TargetPort uint32 `yaml:"targetPort,omitempty"`
}

// JWTConfig contains JWT token configuration
type JWTConfig struct {
	AccessTokenPath string `yaml:"accessTokenPath"`
}

// Config is the main configuration structure for Remote Access Agent
type Config struct {
	Version             string                    `yaml:"version"`
	LogLevel            string                    `yaml:"logLevel"`
	GUID                string                    `yaml:"GUID"`
	RemoteAccessManager RemoteAccessManagerConfig `yaml:"remoteAccessManager"`
	Proxy               ProxyConfig               `yaml:"proxy"`
	MetricsEndpoint     string                    `yaml:"metricsEndpoint"`
	MetricsInterval     time.Duration             `yaml:"metricsInterval"`
	StatusEndpoint      string                    `yaml:"statusEndpoint"`
	JWT                 JWTConfig                 `yaml:"jwt"`
}

// New creates a new Remote Access Agent configuration from a file path.
// It validates the configuration and sets default values where appropriate.
func New(cfgPath string) (*Config, error) {
	if cfgPath == "" {
		return nil, fmt.Errorf("config file path is required")
	}

	// Read config file (ReadFileNoLinks prevents symlink attacks)
	content, err := utils.ReadFileNoLinks(cfgPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse YAML
	var cfg Config
	if err := yaml.Unmarshal(content, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Set default values
	cfg.setDefaults()

	// Validate configuration
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// setDefaults sets default values for configuration fields if they are not set
func (cfg *Config) setDefaults() {
	// Default proxy values
	if cfg.Proxy.Keepalive == 0 {
		cfg.Proxy.Keepalive = 25 * time.Second
	}
	if cfg.Proxy.MaxRetry == 0 {
		cfg.Proxy.MaxRetry = -1 // infinite retry by default
	}

	// Default metrics interval
	if cfg.MetricsInterval == 0 {
		cfg.MetricsInterval = 10 * time.Second
	}

	if cfg.RemoteAccessManager.PollInterval == 0 {
		cfg.RemoteAccessManager.PollInterval = 30 * time.Second
	}

	if strings.TrimSpace(cfg.Proxy.TargetHost) == "" {
		cfg.Proxy.TargetHost = "127.0.0.1"
	}
	if cfg.Proxy.TargetPort == 0 {
		cfg.Proxy.TargetPort = 22
	}
}

// validate checks if required configuration values are set
func (cfg *Config) validate() error {
	if cfg.GUID == "" {
		return fmt.Errorf("GUID is required")
	}

	if cfg.RemoteAccessManager.ServiceURL == "" {
		return fmt.Errorf("remoteAccessManager.serviceURL is required")
	}

	if cfg.Proxy.DefaultEndpoint == "" {
		return fmt.Errorf("Proxy.DefaultEndpoint is required")
	}

	if cfg.JWT.AccessTokenPath == "" {
		return fmt.Errorf("jwt.accessTokenPath is required")
	}

	if cfg.RemoteAccessManager.PollInterval < time.Second {
		return fmt.Errorf("remoteAccessManager.pollInterval must be at least 1s")
	}

	if cfg.Proxy.TargetPort < 1 || cfg.Proxy.TargetPort > 65535 {
		return fmt.Errorf("proxy.targetPort must be between 1 and 65535")
	}

	return nil
}
