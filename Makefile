# Copyright SecureKey Technologies Inc.
#
# SPDX-License-Identifier: Apache-2.0

GOBIN_PATH		=$(abspath .)/build/bin
LINT_VERSION 	?=v1.39.0

DOCKER_OUTPUT_NS      ?=ghcr.io
GATEKEEPER_IMAGE_NAME ?=trustbloc/gatekeeper

ALPINE_VER ?= 3.14
GO_VER     ?= 1.17

.PHONY: all
all: clean checks unit-test bdd-test

.PHONY: checks
checks: license lint

.PHONY: license
license:
	@scripts/check_license.sh

.PHONY: lint
lint:
	@GOBIN=$(GOBIN_PATH) go install github.com/golangci/golangci-lint/cmd/golangci-lint@$(LINT_VERSION)
	@$(GOBIN_PATH)/golangci-lint run
	@cd cmd/gatekeeper && $(GOBIN_PATH)/golangci-lint run -c ../../.golangci.yml
	@cd test/bdd && $(GOBIN_PATH)/golangci-lint run -c ../../.golangci.yml

.PHONY: unit-test
unit-test:
	@go test ./... -count=1 -race -coverprofile=coverage.out -covermode=atomic -timeout=10m
	@cd cmd/gatekeeper && go test ./... -count=1 -race -coverprofile=../../coverage_gatekeeper.out -covermode=atomic -timeout=10m

.PHONY: bdd-test
bdd-test: generate-test-keys gatekeeper-docker
	@cd test/bdd && go test -count=1 -v -cover . -p 1 -timeout=10m -race

.PHONY: generate-test-keys
generate-test-keys:
	@mkdir -p ./test/bdd/fixtures/keys/tls
	@docker run -i --rm \
		-v $(abspath .):/opt/workspace/ace \
		--entrypoint "/opt/workspace/ace/scripts/generate_test_keys.sh" \
		frapsoft/openssl

.PHONY: gatekeeper-docker
gatekeeper-docker:
	@echo "Building Gatekeeper docker image"
	@docker build -f ./images/gatekeeper/Dockerfile --no-cache -t $(DOCKER_OUTPUT_NS)/$(GATEKEEPER_IMAGE_NAME):latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg ALPINE_VER=$(ALPINE_VER) .

.PHONY: clean
clean:
	@rm -rf ./build
	@rm -rf coverage*.out
