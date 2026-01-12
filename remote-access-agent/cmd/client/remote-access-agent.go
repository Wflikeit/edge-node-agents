// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	servicev1 "github.com/open-edge-platform/infra-managers/remote-access/pkg/api/rmtaccessmgr/v1"

	cbackoff "github.com/cenkalti/backoff/v4"

	"github.com/open-edge-platform/edge-node-agents/common/pkg/metrics"
	"github.com/open-edge-platform/edge-node-agents/remote-access-agent/info"
	"github.com/open-edge-platform/edge-node-agents/remote-access-agent/internal/logger"
	"github.com/open-edge-platform/edge-node-agents/remote-access-agent/internal/proxy"
	grpcclient "github.com/open-edge-platform/edge-node-agents/remote-access-agent/internal/rmtaccessconfmgr_client"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

var log = logger.Logger

func main() {
	if err := run(); err != nil {
		log.Errorf("❌ fatal error: %v", err)
		os.Exit(1)
	}
}

func run() error {
	log.Infof("Starting %s - %s", info.Component, info.Version)

	addr := envOrDefault("RA_SVC_ADDR", "localhost:50051")
	useInsecure := envOrDefault("GRPC_INSECURE", "false") == "false"

	// SIGINT/SIGTERM → cancel
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Initialize metrics
	metricsEndpoint := envOrDefault("METRICS_ENDPOINT", "unix:///run/platform-observability-agent/platform-observability-agent.sock")
	metricsInterval := 10 * time.Second // TODO: load from config when config integration is done
	shutdown, err := metrics.Init(ctx, metricsEndpoint, metricsInterval, info.Component, info.Version)
	if err != nil {
		log.Errorf("Initialization of metrics failed: %v", err)
	} else {
		log.Info("Metrics collection started")
		defer func() {
			err = shutdown(ctx)
			if err != nil && !errors.Is(err, context.Canceled) {
				log.Errorf("Shutting down metrics failed! Error: %v", err)
			}
		}()
	}

	// TLS / insecure creds
	var creds credentials.TransportCredentials
	if useInsecure {
		creds = insecure.NewCredentials()
		log.Warn("⚠️ using insecure gRPC transport (dev mode)")
	} else {
		c, err := buildTLSCreds(
			envOrDefault("GRPC_CA_CERT", "ca.pem"),
			envOrDefault("GRPC_TLS_SERVER_NAME", ""),
		)
		if err != nil {
			return fmt.Errorf("tls setup: %w", err)
		}
		creds = c
	}

	raCli, closeConn, err := grpcclient.New(ctx, addr, creds)
	if err != nil {
		return fmt.Errorf("dial gRPC: %w", err)
	}
	defer func() {
		if err := closeConn(); err != nil {
			log.Warnf("⚠️ close gRPC: %v", err)
		}
	}()

	var access *servicev1.AgentRemoteAccessSpec
	bo := cbackoff.NewExponentialBackOff()
	bo.InitialInterval = 100 * time.Millisecond
	bo.MaxInterval = time.Second
	bo.MaxElapsedTime = 15 * time.Second
	if err := cbackoff.Retry(func() error {
		gctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		a, err := raCli.GetSpecByUUID(gctx, "123e4567-e89b-12d3-a456-426614174000")
		if err != nil {
			return err
		}
		if a == nil {
			return fmt.Errorf("not ready")
		}
		access = a
		return nil
	}, cbackoff.WithContext(bo, ctx)); err != nil {
		return fmt.Errorf("get resource access by uuid=%s: %w", "123e4567-e89b-12d3-a456-426614174000", err)
	}
	log.Infof("📦 fetched: uuid=%s", access.GetUuid())

	conn := proxy.New(proxy.DefaultFactory)
	// TODO: Pass proxy config from loaded config file (when config integration is done)
	// For now, use nil - endpoint should come from spec.GetRemoteAccessProxyEndpoint()
	_, closeTunnel, err := conn.Start(ctx, access, nil)
	if err != nil && !isCtxErr(err) {
		return err
	}
	defer closeTunnel()

	<-ctx.Done()
	log.Info("👋 client shutting down gracefully")
	return nil
}

// --- helpers ---
func envOrDefault(key, def string) string {
	if v := os.Getenv(key); strings.TrimSpace(v) != "" {
		return v
	}
	return def
}

func buildTLSCreds(caPath, serverName string) (credentials.TransportCredentials, error) {
	pem, err := os.ReadFile(caPath)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("bad CA pem")
	}
	tlsCfg := &tls.Config{RootCAs: pool}
	if serverName != "" {
		tlsCfg.ServerName = serverName
	}
	return credentials.NewTLS(tlsCfg), nil
}

func isCtxErr(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
