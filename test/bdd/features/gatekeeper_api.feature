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

  Scenario: Create policy configuration for storing/releasing protected data
    When  an HTTP PUT is sent to "https://localhost:9014/v1/policy/containment-policy"
      """
      {
        "collectors": ["did:example:ray_stantz"],
        "handlers": ["did:example:alter_peck"],
        "approvers": ["did:example:peter_venkman", "did:example:eon_spengler", "did:example:winton_zeddemore"],
        "min_approvers": 2
      }
      """
    Then  response status is "200 OK"

  @wip
  Scenario: Protect a social media handle
    Given did owner with name "Intake Processor"
    And Intake Processor wants to convert "@thanos27" social media handle into a DID
    When  an HTTP POST signed by "Intake Processor" is sent to "https://localhost:9014/v1/protect"
      """
      {
        "target": "{{ .SocialMediaHandle }}",
        "policy": "{{ .PolicyID }}"
      }
      """
    Then  response status is "200 OK"
    And  response contains non-empty "did"

    @wip
    Scenario: Create a new Release transaction on a DID
      Given did owner with name "Intake Processor"
        And a social media handle "@big_pikachu" was converted into a DID by "Intake Processor"
        And Handler decides to request release of that DID
      When  an HTTP POST is sent to "https://localhost:9014/v1/release"
        """
        {
          "did": "{{ .DID }}"
        }
        """
    Then  response status is "200 OK"
    And  response contains non-empty "ticket_id"
