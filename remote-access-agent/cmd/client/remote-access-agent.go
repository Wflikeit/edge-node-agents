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
	"github.com/open-edge-platform/edge-node-agents/common/pkg/utils"
	"github.com/open-edge-platform/edge-node-agents/remote-access-agent/info"
	"github.com/open-edge-platform/edge-node-agents/remote-access-agent/internal/config"
	"github.com/open-edge-platform/edge-node-agents/remote-access-agent/internal/logger"
	"github.com/open-edge-platform/edge-node-agents/remote-access-agent/internal/proxy"
	grpcclient "github.com/open-edge-platform/edge-node-agents/remote-access-agent/internal/rmtaccessconfmgr_client"
	"github.com/open-edge-platform/edge-node-agents/remote-access-agent/internal/tenantjwt"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

const AGENT_NAME = "remote-access-agent"

// How long to wait between successful RAM polls when there is no ACTIVE spec yet.
const configPollInterval = 30 * time.Second

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

	tenantID, err := tenantjwt.FromAccessTokenFile(cfg.JWT.AccessTokenPath)
	if err != nil {
		return fmt.Errorf("tenantID from JWT (realm_access roles {tenantUUID}_...): %w", err)
	}
	log.Infof("RAM tenantID: %s", tenantID)

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

	var wg sync.WaitGroup
	wg.Add(1)
	go sendHealthStatus(&wg, ctx, cfg.StatusEndpoint)

	conn := proxy.New(proxy.DefaultFactory)
	proxyCfg := &proxy.StartConfig{
		DefaultEndpoint: cfg.Proxy.DefaultEndpoint,
		KeepAlive:       cfg.Proxy.Keepalive,
		MaxRetryCount:   cfg.Proxy.MaxRetry,
	}

	rpcBo := cbackoff.NewExponentialBackOff()
	rpcBo.InitialInterval = 500 * time.Millisecond
	rpcBo.MaxInterval = 30 * time.Second
	rpcBo.MaxElapsedTime = 0

	var closeTunnel func() error
	defer func() {
		if closeTunnel != nil {
			if err := closeTunnel(); err != nil {
				log.Warnf("⚠️ close tunnel: %v", err)
			}
		}
	}()

pollLoop:
	for {
		if ctx.Err() != nil {
			break pollLoop
		}

		// Refresh auth context from token file for each poll, so rotated JWTs are picked up.
		ctxAuth := utils.GetAuthContext(ctx, cfg.JWT.AccessTokenPath)
		gctx, cancel := context.WithTimeout(ctxAuth, 8*time.Second)
		resp, err := raCli.GetRemoteAccessConfig(gctx, cfg.GUID, tenantID)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				break pollLoop
			}
			log.Warnf("RAM poll failed: %v", err)
			if sleepOrDone(ctx, rpcBo.NextBackOff()) != nil {
				break pollLoop
			}
			continue
		}
		rpcBo.Reset()

		log.Infof("RAM poll: status=%s", resp.GetStatus().String())

		switch resp.GetStatus() {
		case servicev1.ConfigStatus_CONFIG_STATUS_ACTIVE:
			spec := resp.GetSpec()
			if spec == nil {
				log.Error("RAM returned ACTIVE with nil spec")
				if sleepOrDone(ctx, configPollInterval) != nil {
					break pollLoop
				}
				continue
			}
			log.Infof("remote access active: rac uuid=%s", spec.GetUuid())
			_, closeFn, err := conn.Start(ctx, spec, proxyCfg)
			if err != nil {
				if isCtxErr(err) || ctx.Err() != nil {
					break pollLoop
				}
				log.Warnf("proxy start failed: %v", err)
				if sleepOrDone(ctx, configPollInterval) != nil {
					break pollLoop
				}
				continue
			}
			closeTunnel = closeFn
			<-ctx.Done()
			break pollLoop

		case servicev1.ConfigStatus_CONFIG_STATUS_NONE:
			log.Debugf("RAM: no remote access configuration for this host yet (NONE)")
			if sleepOrDone(ctx, configPollInterval) != nil {
				break pollLoop
			}

		case servicev1.ConfigStatus_CONFIG_STATUS_PENDING:
			log.Debugf("RAM: remote access configuration pending")
			if sleepOrDone(ctx, configPollInterval) != nil {
				break pollLoop
			}

		case servicev1.ConfigStatus_CONFIG_STATUS_DISABLED:
			log.Infof("RAM: remote access disabled for this host")
			if sleepOrDone(ctx, configPollInterval) != nil {
				break pollLoop
			}

		case servicev1.ConfigStatus_CONFIG_STATUS_ERROR:
			code := ""
			if ce := resp.GetError(); ce != nil {
				code = ce.GetCode()
			}
			log.Warnf("RAM: configuration error (code=%q)", code)
			if sleepOrDone(ctx, configPollInterval) != nil {
				break pollLoop
			}

		default:
			log.Warnf("RAM: unexpected status %v", resp.GetStatus())
			if sleepOrDone(ctx, configPollInterval) != nil {
				break pollLoop
			}
		}
	}

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

func sleepOrDone(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		d = time.Millisecond
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
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
