// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	servicev1 "github.com/open-edge-platform/infra-managers/remote-access/pkg/api/rmtaccessmgr/v1"

	cbackoff "github.com/cenkalti/backoff/v4"
	"github.com/sirupsen/logrus"

	"github.com/open-edge-platform/edge-node-agents/common/pkg/metrics"
	"github.com/open-edge-platform/edge-node-agents/common/pkg/status"
	"github.com/open-edge-platform/edge-node-agents/remote-access-agent/info"
	"github.com/open-edge-platform/edge-node-agents/remote-access-agent/internal/config"
	"github.com/open-edge-platform/edge-node-agents/remote-access-agent/internal/logger"
	"github.com/open-edge-platform/edge-node-agents/remote-access-agent/internal/proxy"
	grpcclient "github.com/open-edge-platform/edge-node-agents/remote-access-agent/internal/rmtaccessconfmgr_client"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

const AGENT_NAME = "remote-access-agent"

var log = logger.Logger

func init() {
	flag.String("config", "", "Config file path")
}

func main() {
	flag.Parse()
	if err := run(); err != nil {
		log.Errorf("❌ fatal error: %v", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.Lookup("config").Value.String()
	cfg, err := config.New(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Set log level from config
	setLogLevel(cfg.LogLevel)

	log.Infof("Starting %s - %s", info.Component, info.Version)

	addr := cfg.RemoteAccessManager.ServiceURL
	useInsecure := envOrDefault("GRPC_INSECURE", "false") == "false"

	// SIGINT/SIGTERM → cancel
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Initialize metrics
	shutdown, err := metrics.Init(ctx, cfg.MetricsEndpoint, cfg.MetricsInterval, info.Component, info.Version)
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
		a, err := raCli.GetSpecByUUID(gctx, cfg.GUID)
		if err != nil {
			return err
		}
		if a == nil {
			return fmt.Errorf("not ready")
		}
		access = a
		return nil
	}, cbackoff.WithContext(bo, ctx)); err != nil {
		return fmt.Errorf("get resource access by uuid=%s: %w", cfg.GUID, err)
	}
	log.Infof("📦 fetched: uuid=%s", access.GetUuid())

	conn := proxy.New(proxy.DefaultFactory)
	proxyCfg := &proxy.StartConfig{
		DefaultEndpoint: cfg.Proxy.DefaultEndpoint,
		KeepAlive:       cfg.Proxy.Keepalive,
		MaxRetryCount:   cfg.Proxy.MaxRetry,
	}
	_, closeTunnel, err := conn.Start(ctx, access, proxyCfg)
	if err != nil && !isCtxErr(err) {
		return err
	}
	defer closeTunnel()

	// Initialize and start status reporting
	var wg sync.WaitGroup
	wg.Add(1)
	go sendHealthStatus(&wg, ctx, cfg.StatusEndpoint)

	<-ctx.Done()
	log.Info("👋 client shutting down gracefully")
	wg.Wait()
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

func setLogLevel(logLevel string) {
	switch strings.ToLower(logLevel) {
	case "debug":
		log.Logger.SetLevel(logrus.DebugLevel)
	case "error":
		log.Logger.SetLevel(logrus.ErrorLevel)
	default:
		log.Logger.SetLevel(logrus.InfoLevel)
	}
}

// sendHealthStatus sends health status (Ready/NotReady) periodically to the status service
func sendHealthStatus(wg *sync.WaitGroup, ctx context.Context, statusServerEndpoint string) {
	defer wg.Done()

	statusClient, statusInterval := initStatusClientAndTicker(ctx, statusServerEndpoint)
	if statusClient == nil {
		return // Failed to initialize, exit gracefully
	}

	ticker := time.NewTicker(statusInterval)
	defer ticker.Stop()

	// Send initial Ready status
	if err := statusClient.SendStatusReady(ctx, AGENT_NAME); err != nil {
		log.Errorf("Failed to send initial status Ready: %v", err)
	} else {
		log.Debug("Status Ready sent")
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Agent is running, so report as Ready
			if err := statusClient.SendStatusReady(ctx, AGENT_NAME); err != nil {
				log.Errorf("Failed to send status Ready: %v", err)
			} else {
				log.Debug("Status Ready sent")
			}
		}
	}
}

// initStatusClientAndTicker initializes the status client and retrieves the status interval
func initStatusClientAndTicker(ctx context.Context, statusServer string) (*status.StatusClient, time.Duration) {
	statusClient, err := status.InitClient(statusServer)
	if err != nil {
		log.Errorf("Failed to initialize status client: %v", err)
		return nil, 0
	}

	var interval time.Duration
	op := func() error {
		var err error
		interval, err = statusClient.GetStatusInterval(ctx, AGENT_NAME)
		if err != nil {
			log.Errorf("Failed to get status interval: %v", err)
		}
		return err
	}

	// Retry to get status interval (high number of retries as retries would mostly indicate a problem with the status server)
	bo := cbackoff.NewExponentialBackOff()
	err = cbackoff.Retry(op, cbackoff.WithContext(cbackoff.WithMaxRetries(bo, 30), ctx))
	if err != nil {
		log.Warnf("Failed to get status interval, defaulting to 10 seconds: %v", err)
		interval = 10 * time.Second
	}

	return statusClient, interval
}
