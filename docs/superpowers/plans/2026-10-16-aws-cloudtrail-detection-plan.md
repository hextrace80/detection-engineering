# AWS CloudTrail Detection Lab Implementation Plan

> **For implementation:** Follow this plan task by task. The first working slice stays deliberately narrow: CloudTrail management events, one IAM detection, and the existing Tines intake.

## Goal

Prove one cloud-detection path from source telemetry through triage:

`AWS IAM CreateAccessKey` -> `CloudTrail` -> `S3` -> `SQS` -> `Elastic` -> `Elastic detection rule` -> `Tines triage story`.

CloudTrail **management events** are AWS API/control-plane actions. Lab v1 uses a single region (`us-east-1`) and excludes VPC Flow Logs, application logs, data events, automatic remediation, and production credentials.

## Architecture decisions

- **CloudTrail** audits the AWS API action; it is the telemetry source.
- **S3** is the durable private store for CloudTrail log objects.
- **SQS** is the durable notification queue Elastic polls to discover newly delivered log objects.
- The Elastic AWS CloudTrail integration retrieves logs from S3 after receiving SQS notifications.
- The first rule detects `iam.amazonaws.com` / `CreateAccessKey`, mapped to MITRE ATT&CK `T1098` (Account Manipulation).
- The existing Tines webhook is shared intake. Endpoint and AWS alerts use separate normalizers because their evidence schemas differ.
- Use a disposable, non-privileged IAM test user. Create a key only to generate the alert; never use it; delete it immediately.

## Task 1: Create and document the AWS audit-log path

**Files:**
- Create: `docs/aws-lab-runbook.md`

1. In the lab AWS account, choose `us-east-1` and create:
   - Trail: `detection-engineering-cloudtrail`
   - S3 bucket: `detection-engineering-cloudtrail-<account-id>`
   - SQS queue: `detection-engineering-cloudtrail-notifications`
   - Dead-letter queue: `detection-engineering-cloudtrail-notifications-dlq`
2. Create the S3 bucket with Block Public Access and default encryption enabled. It is long-lived evidence storage and must never be public.
3. Create a standard SQS queue, attach the DLQ after five failed receives, and use 14-day retention. This buffers delivery if Elastic is temporarily unavailable.
4. Create a single-region CloudTrail trail that writes to the S3 bucket. Enable management events for read and write activity; leave data events, Insights, and CloudWatch Logs disabled for the minimal lab.
5. Configure an S3 event notification from the `AWSLogs/` prefix to the SQS queue. Apply the queue policy AWS requires so only this bucket can send messages to this queue.
6. Add `docs/aws-lab-runbook.md` with resource names, Region, cleanup steps, and short explanations of CloudTrail/S3/SQS. Exclude keys, webhook URLs, account IDs, and secrets.
7. Produce a harmless IAM read action, then confirm a CloudTrail object reaches S3 and a message reaches SQS.

**Verification:** CloudTrail logging is enabled; S3 contains `AWSLogs/` objects; SQS reports an available message after the benign action.

## Task 2: Create a least-privileged Elastic ingestion identity

**Files:**
- Modify: `docs/aws-lab-runbook.md`

1. Create an IAM user or role called `elastic-cloudtrail-ingestion`. IAM is AWS's identity and permissions service; this identity lets Elastic read only the delivery pipeline.
2. Attach a customer-managed policy granting only:
   - `s3:ListBucket` on `detection-engineering-cloudtrail-<account-id>`
   - `s3:GetObject` on `detection-engineering-cloudtrail-<account-id>/AWSLogs/*`
   - `sqs:GetQueueUrl`, `sqs:GetQueueAttributes`, `sqs:ReceiveMessage`, `sqs:DeleteMessage`, and `sqs:ChangeMessageVisibility` on `detection-engineering-cloudtrail-notifications`
3. Do not grant wildcard administration, IAM write access, or access to unrelated buckets or queues.
4. If Fleet requires access keys, create them for this one ingestion identity and enter them directly into Elastic. Never place them in Git, the runbook, screenshots, Tines, or chat.
5. Record the identity name and permitted AWS services in the runbook, never secret values.

**Verification:** The identity reads the designated queue and CloudTrail objects but cannot modify IAM, CloudTrail, or unrelated storage.

## Task 3: Configure Elastic CloudTrail ingestion and validate raw telemetry

**Files:**
- Modify: `docs/aws-lab-runbook.md`

1. In Elastic Fleet, add the AWS integration and select the CloudTrail input that reads from S3 through SQS.
2. Supply only the lab Region, bucket, queue, and `elastic-cloudtrail-ingestion` authentication configuration.
3. Assign it to a healthy Elastic Agent policy.
4. Generate a benign AWS management event. In Discover, verify documents matching `event.dataset: "aws.cloudtrail"`.
5. Record sanitized, observed field paths in the runbook, especially `event.dataset`, `aws.cloudtrail.event_source`, `aws.cloudtrail.event_name`, and the actor/source-IP/time fields present in the real document.
6. Do not create the rule until actual raw field names are confirmed.

**Verification:** Discover displays CloudTrail data with `event.dataset: aws.cloudtrail`, `event_source`, and `event_name` populated.

## Task 4: Add a tested IAM access-key detection-as-code rule

**Files:**
- Create: `detections/aws_iam_access_key_created.toml`
- Create: `tests/fixtures/aws_iam_access_key_created/positive_create_access_key.json`
- Create: `tests/fixtures/aws_iam_access_key_created/negative_list_users.json`
- Create: `tests/fixtures/aws_iam_access_key_created/test_expectations.json`
- Modify: `tests/run_detection_tests.py`

1. Refactor `tests/run_detection_tests.py` to discover every `test_expectations.json` below `tests/fixtures/`, rather than assuming only the scheduled-task fixture directory.
2. Preserve the existing scheduled-task matcher and dispatch by an explicit matcher name. Add `aws_iam_access_key_created`:

   ```python
   def matches_aws_iam_access_key_created(fixture):
       cloudtrail = fixture["aws"]["cloudtrail"]
       return (
           fixture["event"]["dataset"] == "aws.cloudtrail"
           and cloudtrail["event_source"] == "iam.amazonaws.com"
           and cloudtrail["event_name"] == "CreateAccessKey"
       )
   ```

3. Move any unreachable metadata assertion in the current test runner so every suite validates expected index, severity, risk score, MITRE value, and query fragments.
4. Add a positive representative fixture matching the three CloudTrail fields above and a negative fixture identical except for `event_name: ListUsers`.
5. Add a test expectation using matcher `aws_iam_access_key_created`, index `logs-aws.cloudtrail-*`, severity `medium`, risk score `47`, MITRE `T1098`, and expected query fragments.
6. Add `detections/aws_iam_access_key_created.toml` in the repository's current TOML style. Use rule ID `4a0fce7d-c4a7-4c69-89e5-902f1a3fe276`, `type = "query"`, and:

   ```text
   event.dataset: "aws.cloudtrail" and
   aws.cloudtrail.event_source: "iam.amazonaws.com" and
   aws.cloudtrail.event_name: "CreateAccessKey"
   ```

7. State that triage must review actor, target user, source IP, and business purpose.

**Verification:** `python tests/run_detection_tests.py` passes the original scheduled-task suite and the positive/negative CloudTrail suite.

## Task 5: Use the existing CI/CD path and deploy after review

**Files:**
- Modify: `.github/workflows/toml_mitre_validation.yml`
- Modify: `README.md` after live validation

1. Rename the workflow step `Run scheduled-task fixture tests` to `Run detection fixture tests`; retain `python tests/run_detection_tests.py`.
2. Create a dedicated branch, push it, and confirm TOML validation, MITRE validation, and both fixture suites pass.
3. Review the diff, open a pull request, and merge only when checks are green.
4. Let the existing `elastic_sync.yml` deploy the merged rule. In Elastic Security, confirm the enabled rule uses the confirmed CloudTrail fields and index.
5. Update `README.md` only after the live rule validation succeeds.

**Verification:** GitHub Actions passes and the new rule appears enabled in Elastic Security with the intended query.

## Task 6: Route the AWS alert through Tines and test end to end

**Files:**
- Modify: `docs/aws-lab-runbook.md`
- Modify: `PORTFOLIO_LOG.md` after live validation

1. Reuse the current Elastic-to-Tines webhook connector and minimal body:

   ```json
   {
     "source": "elastic",
     "alert": {
       "alert_id": "{{alert.id}}",
       "rule_name": "{{rule.name}}",
       "rule_id": "{{rule.id}}"
     }
   }
   ```

2. In Tines, add a Condition action after `receive_elastic_alert` called `route_alert_family`. Route the scheduled-task rule ID to its existing normalizer and AWS rule ID `4a0fce7d-c4a7-4c69-89e5-902f1a3fe276` to `normalize_aws_iam_access_key_alert`.
3. Use this minimal AWS analyst schema:

   ```json
   {
     "triage": {
       "status": "new",
       "requires_human_decision": true,
       "automated_enrichment": "not_configured_lab"
     },
     "detection": {
       "source": "<<receive_elastic_alert.body.source>>",
       "alert_id": "<<receive_elastic_alert.body.alert.alert_id>>",
       "rule_name": "<<receive_elastic_alert.body.alert.rule_name>>",
       "rule_id": "<<receive_elastic_alert.body.alert.rule_id>>",
       "family": "aws_iam"
     },
     "evidence": {
       "collection_status": "not_included_in_minimal_webhook_payload"
     }
   }
   ```

4. Add `deduplicate_aws_alert` with `detection.alert_id` as the key and the same lab lookback as the current story.
5. Create a disposable `cloudtrail-access-key-test` IAM user, create one access key, and never use it. Verify the action reaches S3, SQS, Elastic, the rule, and Tines Events.
6. Delete the test key and user immediately. Confirm cleanup actions appear in CloudTrail.
7. Record redacted evidence in the runbook. Update the portfolio only after the successful live test and retain the distinction between lab work and Oracle production experience.

**Verification:** One `CreateAccessKey` operation creates one Elastic alert and one normalized Tines AWS triage event; replaying that Elastic alert is suppressed by deduplication.

## Final acceptance checklist

- [ ] CloudTrail management events land privately in S3.
- [ ] SQS notifies Elastic of new CloudTrail objects.
- [ ] Elastic displays `aws.cloudtrail` events.
- [ ] The new rule has positive and negative fixture coverage and passes CI.
- [ ] A disposable IAM key test creates a real Elastic alert.
- [ ] Tines routes, normalizes, and deduplicates AWS alerts separately from endpoint alerts.
- [ ] Test credentials are deleted; no secrets are committed or documented.
