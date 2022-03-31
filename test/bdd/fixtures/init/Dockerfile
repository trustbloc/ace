#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

ARG ALPINE_VER

FROM alpine:${ALPINE_VER}
LABEL org.opencontainers.image.source https://github.com/trustbloc/ace

RUN apk add --no-cache \
    bash \
    curl \
    jq \
    xxd \
    coreutils;

ENTRYPOINT ["/opt/configure.sh"]
