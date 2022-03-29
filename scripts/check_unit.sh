#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
set -e

echo "Running $0"

go generate ./...
pwd=`pwd`
touch "$pwd"/coverage.out

amend_coverage_file () {
if [ -f profile.out ]; then
     cat profile.out >> "$pwd"/coverage.out
     rm profile.out
fi
}

# Running ACE unit tests
PKGS=`go list github.com/trustbloc/ace/... 2> /dev/null | \
                                                  grep -v /mocks`
go test $PKGS -count=1 -race -coverprofile=profile.out -covermode=atomic -timeout=10m
amend_coverage_file

# Running Gatekeeper unit tests
cd cmd/gatekeeper
PKGS=`go list github.com/trustbloc/ace/cmd/gatekeeper/... 2> /dev/null | \
                                                 grep -v /mocks`
go test $PKGS -count=1 -race -coverprofile=profile.out -covermode=atomic -timeout=10m
amend_coverage_file
cd "$pwd"

# Running vault-server unit tests
cd cmd/vault-server
PKGS=`go list github.com/trustbloc/ace/cmd/vault-server/... 2> /dev/null | \
                                                 grep -v /mocks`
go test $PKGS -count=1 -race -coverprofile=profile.out -covermode=atomic -timeout=10m
amend_coverage_file
cd "$pwd"
