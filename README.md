[![Release](https://img.shields.io/github/release/trustbloc/ace.svg?style=flat-square)](https://github.com/trustbloc/ace/releases/latest)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://raw.githubusercontent.com/trustbloc/ace/main/LICENSE)
[![Godocs](https://img.shields.io/badge/godoc-reference-blue.svg)](https://godoc.org/github.com/trustbloc/ace)

[![Build Status](https://github.com/trustbloc/ace/actions/workflows/build.yml/badge.svg)](https://github.com/trustbloc/ace/actions/workflows/build.yml)
[![codecov](https://codecov.io/gh/trustbloc/ace/branch/main/graph/badge.svg)](https://codecov.io/gh/trustbloc/ace)
[![Go Report Card](https://goreportcard.com/badge/github.com/trustbloc/ace)](https://goreportcard.com/report/github.com/trustbloc/ace)

# ACE

ACE contains components to support Anonymous Comparator and Extractor flows.

## Gatekeeper

Gatekeeper helps to ensure that there are multiple authorizations for accessing protected data under the given policy.
It supports the following operations:
- create policy configurations for storing and releasing protected data;
- convert sensitive PII data into DID;
- create release transactions (tickets) on DID;
- accept authorizations for a ticket from approvers;
- accept release request for a ticket that has completed the authorization sequence.

### Running Gatekeeper as a Docker container

Build a docker image using `make gatekeeper-docker` and start server with the following command:

```sh
$ docker run -p 9014:9014 ghcr.io/trustbloc/gatekeeper:latest start [flags]
```

### Flags

| Flag                   | Environment variable    | Description                                                                       |
|------------------------|-------------------------|-----------------------------------------------------------------------------------|
| --api-token            | GK_REST_API_TOKEN       | Bearer token used for a token protected api calls.                                |
| --bloc-domain          | GK_BLOC_DOMAIN          | Bloc domain.                                                                      |
| --context-provider-url | GK_CONTEXT_PROVIDER_URL | Remote context provider URL to get JSON-LD contexts from.                         |
| --csh-url              | GK_CSH_URL              | URL of the Confidential Storage Hub.                                              |
| --database-prefix      | DATABASE_PREFIX         | An optional prefix to be used when creating and retrieving underlying databases.  |
| --database-timeout     | DATABASE_TIMEOUT        | Total time in seconds to wait until the datasource is available before giving up. |
| --database-url         | DATABASE_URL            | Database URL with credentials if required.                                        |
| --did-anchor-origin    | GK_DID_ANCHOR_ORIGIN    | DID anchor origin.                                                                |
| --did-resolver-url     | GK_DID_RESOLVER_URL     | DID Resolver URL.                                                                 |
| --host-url             | GK_HOST_URL             | Host URL to run the gatekeeper instance on. Format: HostName:Port.                |
| --tls-cacerts          | GK_TLS_CACERTS          | Comma-separated list of CA certs path.                                            |
| --tls-serve-cert       | GK_TLS_SERVE_CERT       | Path to the server certificate to use when serving HTTPS.                         |
| --tls-serve-key        | GK_TLS_SERVE_KEY        | Path to the private key to use when serving HTTPS.                                |
| --tls-systemcertpool   | GK_TLS_SYSTEMCERTPOOL   | Use system certificate pool. Possible values [true] [false].                      |
| --vault-server-url     | GK_VAULT_SERVER_URL     | URL of the vault server.                                                          |
| --vc-issuer-profile    | GK_VC_ISSUER_PROFILE    | Profile of the VC VCIssuer service.                                               |
| --vc-issuer-url        | GK_VC_ISSUER_URL        | URL of the VC Issuer service.                                                     |
| --request-tokens       | GK_REQUEST_TOKENS       | Tokens used for HTTP requests to other services.                                  |

### REST API

#### Generate OpenAPI specification

The OpenAPI spec for the `gatekeeper` can be generated by running the following target from the project root directory:

```sh
$ make open-api-spec
```

The generated spec can be found under `./test/bdd/fixtures/spec/openAPI.yml`.

#### Run OpenAPI demo

Start the OpenAPI demo by running

```sh
$ make open-api-demo
```

Once the services are up, click [here](http://localhost:8089/openapi/) to launch the OpenAPI interface.

## Running tests

### Prerequisites

- Go 1.18
- Docker
- Docker-Compose
- Make

### Targets

```sh
# run all build targets
$ make all

# run license and linter checks
$ make checks

# run unit tests
$ make unit-test

# run bdd tests
$ make bdd-test
```

## Contributing

Thank you for your interest in contributing. Please see our [community contribution guidelines](https://github.com/trustbloc/community/blob/main/CONTRIBUTING.md)
for more information.

## License

Apache License, Version 2.0 (Apache-2.0). See the [LICENSE](LICENSE) file.
