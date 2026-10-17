# Elastic to Tines SOAR Enrichment Workflow

## Goal

Automatically send Elastic detection alerts to Tines for enrichment, evidence collection, and analyst triage. Version 1 does not perform automatic containment.

## Trigger

The Elastic rule `Scheduled Task Creation via Schtasks` creates an alert. An Elastic webhook action sends the alert to a Tines webhook.

## Workflow

1. Tines receives and validates the Elastic alert.
2. Tines deduplicates by Elastic alert ID.
3. Tines enriches the alert using Elastic REST APIs.
4. Tines collects related host, user, and process evidence.
5. Tines creates a normalized analyst triage record.
6. An analyst reviews the evidence and decides whether containment is needed.

## Security

- Store Elastic and enrichment API keys in Tines credential storage.
- Keep credentials out of Git and Story definitions.
- Give the Elastic API key read-only permissions for enrichment.
- Validate inbound webhook requests.
- Do not automate containment in version 1.

## Failure Handling

- Retry temporary REST API failures.
- Continue with a partial triage record if optional enrichment fails.
- Mark duplicate alerts instead of creating duplicate cases.
- Record missing evidence explicitly.

## Success Criteria

- A new scheduled-task alert automatically reaches Tines.
- Tines retrieves related evidence through REST APIs.
- Tines produces an analyst-ready triage record.
- The workflow can be demonstrated without exposing secrets.