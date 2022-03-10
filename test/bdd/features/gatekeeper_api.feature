#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@gatekeeper
Feature: Gatekeeper API
  Scenario: Service health check
    Given Gatekeeper is running on "localhost" port "9014"
    When  an HTTP GET is sent to "https://localhost:9014/healthcheck"
    Then  the JSON path "status" of the response equals "success"
