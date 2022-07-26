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
    Then  response status is "200 OK"
     And  response contains "status" with value "success"

  Scenario: Create policy configuration for storing/releasing protected data
    When  an HTTP PUT with bearer token "gk_token" is sent to "https://localhost:9014/v1/policy/containment-policy"
          """
          {
            "collectors": ["did:example:ray_stantz"],
            "handlers": ["did:example:alter_peck"],
            "approvers": ["did:example:peter_venkman", "did:example:eon_spengler", "did:example:winton_zeddemore"],
            "min_approvers": 2
          }
          """
    Then  response status is "200 OK"

  Scenario: Protect a social media handle
    Given did owner with name "Intake Processor"
      And policy configuration with ID "intake-policy"
          """
          {
            "collectors": ["{{ .GetDID "Intake Processor" }}"]
          }
          """
    When  an HTTP POST with "(request-target),date,digest" headers signed by "Intake Processor" is sent to "https://localhost:9014/v1/protect" with body
          """
          {
            "target": "@thanos",
            "policy": "intake-policy"
          }
          """
    Then  response status is "200 OK"
     And  response contains non-empty "did"

  Scenario: Create a new release transaction on a DID
    Given did owner with name "Intake Processor"
      And did owner with name "Handler"
      And policy configuration with ID "release-policy"
          """
          {
            "collectors": ["{{ .GetDID "Intake Processor" }}"],
            "handlers": ["{{ .GetDID "Handler" }}"]
          }
          """
      And social media handle "@big_pikachu" converted into DID by "Intake Processor"
    When  an HTTP POST with "(request-target),date,digest" headers signed by "Handler" is sent to "https://localhost:9014/v1/release" with body
          """
          {
            "did": "{{ .Value "targetDID" }}"
          }
          """
    Then  response status is "200 OK"
     And  response contains non-empty "ticket_id"

  Scenario: Authorize a ticket by 2 approvers
    Given did owner with name "Intake Processor"
      And did owner with name "Handler"
      And did owner with name "Approver 1"
      And did owner with name "Approver 2"
      And policy configuration with ID "authorize-policy"
          """
          {
            "collectors": ["{{ .GetDID "Intake Processor" }}"],
            "handlers": ["{{ .GetDID "Handler" }}"],
            "approvers": ["{{ .GetDID "Approver 1" }}", "{{ .GetDID "Approver 2" }}"],
            "min_approvers": 2
          }
          """
      And social media handle "@thanos27" converted into DID by "Intake Processor"
      And release transaction created on DID by "Handler"

    When  an HTTP POST with "(request-target),date" headers signed by "Approver 1" is sent to "https://localhost:9014/v1/release/{ticket_id}/authorize"
    Then  response status is "200 OK"

    When  an HTTP GET with "(request-target),date" headers signed by "Handler" is sent to "https://localhost:9014/v1/release/{ticket_id}/status"
    Then  response status is "200 OK"
     And  response contains "status" with value "COLLECTING"

    When  an HTTP POST with "(request-target),date" headers signed by "Approver 2" is sent to "https://localhost:9014/v1/release/{ticket_id}/authorize"
    Then  response status is "200 OK"

    When  an HTTP GET with "(request-target),date" headers signed by "Handler" is sent to "https://localhost:9014/v1/release/{ticket_id}/status"
    Then  response status is "200 OK"
     And  response contains "status" with value "READY_TO_COLLECT"

  @gatekeeper_e2e
  Scenario: Protect and extract social media handle (e2e flow)
    Given did owner with name "Intake Processor"
      And did owner with name "Handler"
      And did owner with name "Approver 1"
      And did owner with name "Approver 2"
      And policy configuration with ID "full-scenario-policy"
          """
          {
            "collectors": ["{{ .GetDID "Intake Processor" }}"],
            "handlers": ["{{ .GetDID "Handler" }}"],
            "approvers": ["{{ .GetDID "Approver 1" }}", "{{ .GetDID "Approver 2" }}"],
            "min_approvers": 2
          }
          """

    When  an HTTP POST with "(request-target),date,digest" headers signed by "Intake Processor" is sent to "https://GATEKEEPER_HOST/v1/protect" with body
          """
          {
            "target": "@thanos27",
            "policy": "full-scenario-policy"
          }
          """
    Then  response status is "200 OK"
     And  response contains non-empty "did"

    When  an HTTP POST with "(request-target),date,digest" headers signed by "Handler" is sent to "https://GATEKEEPER_HOST/v1/release" with body
          """
          {
            "did": "{{ .Value "did" }}"
          }
          """
    Then  response status is "200 OK"
     And  response contains non-empty "ticket_id"

    When  an HTTP POST with "(request-target),date" headers signed by "Approver 1" is sent to "https://GATEKEEPER_HOST/v1/release/{ticket_id}/authorize"
    Then  response status is "200 OK"

    When  an HTTP POST with "(request-target),date" headers signed by "Approver 2" is sent to "https://GATEKEEPER_HOST/v1/release/{ticket_id}/authorize"
    Then  response status is "200 OK"

    When  an HTTP POST with "(request-target),date" headers signed by "Handler" is sent to "https://GATEKEEPER_HOST/v1/release/{ticket_id}/collect"
    Then  response status is "200 OK"
     And  response contains non-empty "query_id"

    When  an HTTP POST is sent to "https://GATEKEEPER_HOST/v1/extract"
          """
          {
            "query_id": "{{ .Value "query_id" }}"
          }
          """
    Then  response status is "200 OK"
     And  response contains "target" with value "@thanos27"
