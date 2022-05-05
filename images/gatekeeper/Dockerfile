#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

ARG GO_VER
ARG ALPINE_VER

FROM golang:${GO_VER}-alpine${ALPINE_VER} as builder

RUN apk update && apk add git && apk add ca-certificates
RUN adduser -D -g '' appuser
COPY . $GOPATH/src/github.com/trustbloc/ace/
WORKDIR $GOPATH/src/github.com/trustbloc/ace/

RUN cd cmd/gatekeeper && CGO_ENABLED=0 go build -o /usr/bin/gatekeeper main.go

FROM alpine:${ALPINE_VER}
LABEL org.opencontainers.image.source https://github.com/trustbloc/ace

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /usr/bin/gatekeeper /usr/bin/gatekeeper
USER appuser

ENTRYPOINT ["/usr/bin/gatekeeper"]
