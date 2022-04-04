# Copyright SecureKey Technologies Inc.
#
# SPDX-License-Identifier: Apache-2.0

GOBIN_PATH		=$(abspath .)/build/bin
LINT_VERSION 	?=v1.44.2
MOCK_VERSION 	?=v1.6.0

DOCKER_OUTPUT_NS      ?=ghcr.io
GATEKEEPER_IMAGE_NAME ?=trustbloc/gatekeeper
COMPARATOR_REST_IMAGE_NAME          ?= trustbloc/comparator-server
CONFIDENTIAL_STORAGE_HUB_IMAGE_NAME ?= trustbloc/hub-confidential-storage
VAULT_SERVER_IMAGE_NAME				?= trustbloc/vault-server

ALPINE_VER ?= 3.14
GO_VER     ?= 1.18

GATE_KEEPER_PATH=cmd/gatekeeper
COMPARATOR_REST_PATH=cmd/comparator-rest
CONFIDENTIAL_STORAGE_HUB_PATH=cmd/confidential-storage-hub

# OpenAPI spec
OPENAPI_DOCKER_IMG=quay.io/goswagger/swagger
OPENAPI_SPEC_PATH=.build/rest/openapi/spec
OPENAPI_DOCKER_IMG_VERSION=v0.26.0

OS := $(shell uname)
ifeq  ($(OS),$(filter $(OS),Darwin Linux))
	PATH:=$(PATH):$(GOBIN_PATH)
else
	PATH:=$(PATH);$(subst /,\\,$(GOBIN_PATH))
endif

.PHONY: all
all: clean checks unit-test bdd-test

.PHONY: checks
checks: license lint

.PHONY: license
license:
	@scripts/check_license.sh

.PHONY: mocks
mocks:
	@GOBIN=$(GOBIN_PATH) go install github.com/golang/mock/mockgen@$(MOCK_VERSION)
	@go generate ./...

.PHONY: lint
lint: mocks
	@GOBIN=$(GOBIN_PATH) go install github.com/golangci/golangci-lint/cmd/golangci-lint@$(LINT_VERSION)
	@$(GOBIN_PATH)/golangci-lint run
	@cd cmd/gatekeeper && $(GOBIN_PATH)/golangci-lint run -c ../../.golangci.yml
	@cd test/bdd && $(GOBIN_PATH)/golangci-lint run -c ../../.golangci.yml

.PHONY: unit-test
unit-test: mocks
	@scripts/check_unit.sh

.PHONY: bdd-test
bdd-test: generate-test-keys gatekeeper-docker comparator-rest-docker vault-server-docker confidential-storage-hub-docker
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

.PHONY: vault-server-docker
vault-server-docker:
	@echo "Building vault-server docker image"
	@docker build -f ./images/vault-server/Dockerfile --no-cache -t $(DOCKER_OUTPUT_NS)/$(VAULT_SERVER_IMAGE_NAME):latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg ALPINE_VER=$(ALPINE_VER) .

.PHONY: comparator-rest-docker
comparator-rest-docker:
	@echo "Building comparator rest docker image"
	@docker build -f ./images/comparator-rest/Dockerfile --no-cache -t $(DOCKER_OUTPUT_NS)/$(COMPARATOR_REST_IMAGE_NAME):latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg ALPINE_VER=$(ALPINE_VER) .

.PHONY: confidential-storage-hub-docker
confidential-storage-hub-docker:
	@echo "Building confidential-storage-hub docker image"
	@docker build -f ./images/confidential-storage-hub/Dockerfile --no-cache -t ${DOCKER_OUTPUT_NS}/${CONFIDENTIAL_STORAGE_HUB_IMAGE_NAME}:latest \
		--build-arg GO_VER=${GO_VER} \
		--build-arg ALPINE_VER=${ALPINE_VER} .

.PHONY: clean
clean:
	@rm -rf ./build
	@rm -rf coverage*.out

.PHONY: generate-models-client-gatekeeper
generate-models-client-gatekeeper:
	@echo "Generating gatekeeper models and client"
	@MODELS_PATH=pkg/restapi/gatekeeper/operation CLIENT_PATH=pkg/client/gatekeeper SPEC_LOC=${GATE_KEEPER_PATH}/openapi.yaml  \
	DOCKER_IMAGE=$(OPENAPI_DOCKER_IMG) DOCKER_IMAGE_VERSION=$(OPENAPI_DOCKER_IMG_VERSION)  \
	scripts/generate-models-client.sh

.PHONY: generate-models-client-comparator
generate-models-client-comparator:
	@echo "Generating comparator models and client"
	@MODELS_PATH=pkg/restapi/comparator/operation CLIENT_PATH=pkg/client/comparator SPEC_LOC=${COMPARATOR_REST_PATH}/docs/openapi.yaml  \
	DOCKER_IMAGE=$(OPENAPI_DOCKER_IMG) DOCKER_IMAGE_VERSION=$(OPENAPI_DOCKER_IMG_VERSION)  \
	scripts/generate-models-client.sh
