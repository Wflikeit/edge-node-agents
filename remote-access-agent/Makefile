# SPDX-FileCopyrightText: (C) 2025 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

SHELL=/bin/bash -o pipefail
REGISTRY := 080137407410.dkr.ecr.us-west-2.amazonaws.com
NAME ?= remote-access-agent
BUILD_DIR ?= build/artifacts
GO_MOD ?= readonly
RA_PACKAGE_BUILD_DIR ?= $(BUILD_DIR)/package
VERSION := $(shell cat VERSION)
COMMIT := $(shell git rev-parse --short HEAD)
ifneq (,$(findstring dev,$(VERSION)))
	PKG_VERSION = $(VERSION)-$(COMMIT)
else
	PKG_VERSION = $(VERSION)
endif
TARBALL_DIR := $(BUILD_DIR)/$(NAME)-$(PKG_VERSION)
RA_VERSION="Remote Access Agent v$(VERSION)-$(COMMIT)"

# Include shared makefile, if it exists
ifneq ("$(wildcard ./common.mk)","")
	include ./common.mk
else
	include ../common.mk
endif

#.PHONY: all build clean help lint list package test fuzztest tarball
.PHONY: all build clean help lint list package fuzztest tarball

all: build lint
#all: build lint test

clean:
	@echo "---MAKEFILE CLEAN---"
	rm -rf build
	@echo "---END MAKEFILE CLEAN---"

lint: golint

rainstall:
	install -d $(DESTDIR)$(PREFIX)/bin
	install $(BUILD_DIR)/$(NAME) $(DESTDIR)$(PREFIX)/bin

rabuild:
	CGO_ENABLED=0 GOARCH=amd64 GOOS=linux \
	go build -buildmode=pie -trimpath -mod=$(GO_MOD) -gcflags="all=-spectre=all -l" -asmflags="all=-spectre=all" -ldflags="all=-s -w -extldflags=-static \
	-X github.com/open-edge-platform/edge-node-agents/remote-access-agent/info.version=$(VERSION) \
	-X github.com/open-edge-platform/edge-node-agents/remote-access-agent/info.commit=$(COMMIT)" \
	-o $(BUILD_DIR)/$(NAME) cmd/remote-access-agent.go

rabuild_with_race:
	CGO_ENABLED=1 go build -race -ldflags=" \
	-X github.com/open-edge-platform/edge-node-agents/remote-access-agent/info.version=$(VERSION) \
	-X github.com/open-edge-platform/edge-node-agents/remote-access-agent/info.commit=$(COMMIT)" \
	-o $(BUILD_DIR)/$(NAME)_race cmd/remote-access-agent.go

rabuild_with_cover:
	CGO_ENABLED=0 go build -cover -covermode count -ldflags=" \
	-X github.com/open-edge-platform/edge-node-agents/remote-access-agent/info.version=$(VERSION) \
	-X github.com/open-edge-platform/edge-node-agents/remote-access-agent/info.commit=$(COMMIT)" \
	-o $(BUILD_DIR)/$(NAME)_cover cmd/remote-access-agent.go

build: rabuild

#test: common-unit-test
#test: common-unit-test

integration_test: rabuild_with_race
	sudo cp test/_dummy.crt /usr/local/share/RA-certificates/_dummy.crt
	sudo update-RA-certificates
	RA_BINARY_PATH=$(shell pwd)/$(BUILD_DIR)/remote-access-agent_race \
	TEST_CONFIG_PATH=$(shell pwd)/test/test_config.yaml \
	TEST_CERT_PATH=$(shell pwd)/test/_dummy.crt \
	TEST_KEY_PATH=$(shell pwd)/test/_dummy.key \
	RA_VERSION="remote-access Agent v$(VERSION)-$(COMMIT)" \
	GORACE="log_path=stdout" \
	# go test -v ./cmd/remote-access-agent/remote-access-agent_test.go

cover_unit:
	mkdir -p $(BUILD_DIR)/coverage/unit
	go test -v ./internal/... -cover -covermode count -args -test.gocoverdir=$(shell pwd)/$(BUILD_DIR)/coverage/unit | tee $(BUILD_DIR)/coverage/unit/unit.out
	go tool covdata percent -i=$(BUILD_DIR)/coverage/unit
	go tool covdata func -i=$(BUILD_DIR)/coverage/unit
#
#cover_integration: rabuild_with_cover
#	mkdir -p $(BUILD_DIR)/coverage/integration
#	GOCOVERDIR=$(shell pwd)/$(BUILD_DIR)/coverage/integration \
#	RA_BINARY_PATH=$(shell pwd)/$(BUILD_DIR)/remote-access-agent_cover \
#	TEST_CONFIG_PATH=$(shell pwd)/test/test_config.yaml \
#	TEST_CERT_PATH=$(shell pwd)/test/_dummy.crt \
#	TEST_KEY_PATH=$(shell pwd)/test/_dummy.key \
#	RA_VERSION="remote-access Agent v$(VERSION)-$(COMMIT)" \
#	go test -v ./cmd/remote-access-agent/remote-access-agent_test.go | tee $(BUILD_DIR)/coverage/integration/integration.out
#	go tool covdata percent -i=$(BUILD_DIR)/coverage/integration
#	go tool covdata func -i=$(BUILD_DIR)/coverage/integration

fuzztest: common-fuzztest

#cover: cover_unit cover_integration
#	go tool covdata textfmt -i=$(BUILD_DIR)/coverage/unit,$(BUILD_DIR)/coverage/integration -o $(BUILD_DIR)/coverage/profile
#	go tool cover -html $(BUILD_DIR)/coverage/profile -o $(BUILD_DIR)/coverage/coverage.html
#	go tool covdata percent -i=$(BUILD_DIR)/coverage/unit,$(BUILD_DIR)/coverage/integration
#	cat $(BUILD_DIR)/coverage/unit/unit.out | go-junit-report -set-exit-code > build/artifacts/report.xml
#	sed -i "s#$(shell pwd)#github.com/open-edge-platform/edge-node-agents/remote-access-agent#g" build/artifacts/coverage/profile
#	gocover-cobertura < $(BUILD_DIR)/coverage/profile > build/artifacts/coverage.xml

#cover_old:
#	mkdir -p build/artifacts
#	go test ./internal/... -coverprofile=build/artifacts/coverage.out -v -covermode count | go-junit-report -set-exit-code > build/artifacts/report.xml
#	go tool cover -html=build/artifacts/coverage.out -o build/artifacts/cover.html
#	gocover-cobertura < build/artifacts/coverage.out > build/artifacts/coverage.xml

package:
	mkdir -p $(RA_PACKAGE_BUILD_DIR)
	cp -r $(shell ls . | grep -v build*) $(RA_PACKAGE_BUILD_DIR)
	cp ../.golangci.yml $(RA_PACKAGE_BUILD_DIR)
	cp -r ../LICENSES ${RA_PACKAGE_BUILD_DIR}
	cp ../common.mk $(RA_PACKAGE_BUILD_DIR)
	sed -i "s#../.golangci.yml#.golangci.yml#" $(RA_PACKAGE_BUILD_DIR)/common.mk
	sed -i "s#VERSION#$(PKG_VERSION)#" $(RA_PACKAGE_BUILD_DIR)/debian/changelog
	sed -i "s#../common.mk#common.mk#" $(RA_PACKAGE_BUILD_DIR)/Makefile
	cd $(RA_PACKAGE_BUILD_DIR); debuild --preserve-env --preserve-envvar PATH -us -uc -b

#package_test:
#	echo "remote-access-agent remote-access-agent/remote-access-orchestrator-url string localhost:12345" | sudo debconf-set-selections
#	sudo apt-get install -y ./$(BUILD_DIR)/remote-access-agent_$(PKG_VERSION)_amd64.deb
#	sudo systemctl enable remote-access-agent
#	sudo systemctl start remote-access-agent
#	systemctl is-active remote-access-agent
#	sudo systemctl disable remote-access-agent
#	sudo apt-get purge -y remote-access-agent

tarball: common-tarball

deb-push: common-deb-push