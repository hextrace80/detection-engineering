# AWS CloudTrail Detection Extension Design

## Objective

Extend the detection-engineering lab with AWS control-plane telemetry while preserving the existing endpoint, network, detection-as-code, Elastic Security, and Tines layers. The first cloud use case detects IAM access-key creation from CloudTrail management events.

## Existing architecture

```text
Parrot attacker ─┐
Windows 11/Sysmon ─┼─> Elastic Security ─> Tines triage
Ubuntu/Zeek ───────┘          ^
                             GitHub detection CI/CD
```

## Target architecture

```text
AWS account
  -> multi-Region CloudTrail management-event trail
  -> encrypted S3 log bucket
  -> SQS new-object notifications
  -> Elastic Agent AWS CloudTrail integration
  -> Elastic Security
  -> Git-managed AWS detection rule
  -> Tines shared intake
  -> AWS-specific normalization, deduplication, and analyst triage
```

The existing Windows scheduled-task normalizer remains endpoint-specific. AWS alerts must use a separate normalizer after shared intake routing, so different event schemas are not mixed.

## First detection

Detect the CloudTrail `CreateAccessKey` management event for IAM users. This provides a focused, reversible lab test and demonstrates monitoring of cloud identity changes.

The test must use a disposable, non-privileged IAM user. The created key must not be used and must be deleted immediately after validation.

## Security boundaries

- Use a dedicated AWS lab account when possible.
- Configure CloudTrail for management events only and one Region initially to control scope and cost.
- Keep the CloudTrail S3 bucket private, encrypted, and separate from application data.
- Use a dedicated least-privilege AWS ingestion identity for Elastic. It may read the designated S3 objects and SQS messages but must not administer AWS resources.
- Store AWS credentials in Elastic/Fleet credential storage; do not store them in TOML, GitHub, Tines events, or source control.
- Keep Tines read-only and human-in-the-loop. This version performs no IAM changes or automated containment.

## Data flow and validation

1. A controlled IAM access-key creation produces a CloudTrail management event.
2. CloudTrail delivers the event to S3 and SQS announces the new object.
3. Elastic Agent collects and parses the record into Elastic.
4. The Git-managed rule detects `CreateAccessKey` and creates an Elastic Security alert.
5. Tines receives the alert, routes it to its AWS path, normalizes it, and deduplicates by Elastic alert ID.

Validate each boundary independently: CloudTrail event history, S3/SQS delivery, Elastic Discover document, Elastic rule execution and alert, then Tines event output. Delete the test key and test user after validation.

## Failure handling

- SQS retains unprocessed delivery notifications for retry when ingestion is unavailable.
- Elastic rule execution results are the source for detection failures.
- Elastic connector-action results are the source for Tines delivery failures.
- No action should disable or modify AWS resources automatically.

## Success criteria

- A controlled `CreateAccessKey` event reaches Elastic as parsed CloudTrail telemetry.
- The detection rule is version controlled, validated in CI, and deployed through the existing workflow.
- Elastic produces one alert for the test event.
- Tines receives and deduplicates the cloud alert through an AWS-specific path.
- Cleanup removes the created access key and disposable test user.
