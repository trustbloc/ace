#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@gatekeeper
Feature: Gatekeeper API
  Background:
    Given Gatekeeper is running on "localhost" port "9014"

  Scenario: Service health check
    When  an HTTP GET is sent to "https://localhost:9014/healthcheck"
    Then  response status is "200 OK"
     And  response contains "status" with value "success"

  Scenario: Protect a social media handle
    Given Intake Processor wants to convert "@thanos27" social media handle into a DID
      And Issuer profile "vc-issuer-gk" is created on "http://localhost:8070" for "localhost:8065"
    When  an HTTP POST is sent to "https://localhost:9014/v1/protect"
      """
      {
        "target": "{{ .SocialMediaHandle }}",
        "policy": "{{ .PolicyID }}"
      }
      """
    Then  response status is "200 OK"
     And  response contains non-empty "did"
