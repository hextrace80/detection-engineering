# Detection Engineering — Elastic Security Lab

Hands-on **detection-as-code** project for authoring, validating, testing, deploying, and monitoring security detections in an Elastic Security lab.

The goal is to treat detections like software: keep rule definitions in Git, review changes, validate metadata and MITRE ATT&CK mappings, test expected behavior, and measure operational health.

> **Project scope:** This is an independent lab/portfolio project, not a production security service. Simulated fixture tests do not execute Elastic KQL or prove end-to-end detection coverage.

## At a glance

- **15 TOML detection definitions** targeting selected Linux auditd, Windows/Sysmon, Zeek, and AWS CloudTrail signals.
- **Python-based validation** for required rule metadata and MITRE ATT&CK technique mappings.
- **Offline positive/negative test fixtures** for selected detections, plus Python tests for correlation, health reporting, and deployment utilities.
- **GitHub Actions** validation and a controlled Elastic rule synchronization workflow.
- **Detection health reporting** for rule inventory, execution status, alert activity, and potential duplicates.
- **Auditd event-processing utilities** for correlation and integration with Elastic.

## Example detections

| Detection | Telemetry / detection idea | ATT&CK |
| --- | --- | --- |
| [Suspicious Linux crontab edit](detections/linux_suspicious_crontab_edit.toml) | auditd process event showing `crontab -e` | T1053.003 — Cron |
| [AWS IAM access key created](detections/aws_iam_access_key_created.toml) | CloudTrail IAM `CreateAccessKey` management event | T1098 — Account Manipulation |
| [Scheduled task creation](detections/scheduled_task_creation_via_schtasks.toml) | Sysmon process creation involving `schtasks.exe` | T1053.005 — Scheduled Task |

These are investigation signals, not proof of malicious intent. Their usefulness depends on telemetry coverage, field mappings, tuning, and validation in the target environment.

## Engineering workflow

```text
Host / cloud / network telemetry
           |
           v
   Elastic data streams
           |
           v
   TOML rule definitions in Git
           |
           v
   GitHub Actions validation
     - TOML field checks
     - ATT&CK mapping checks
     - selected offline fixture tests
           |
           v
   Elastic rule sync on main *
           |
           v
   Rule execution & health review
```

*The [validation and deployment workflow](.github/workflows/elastic_sync.yml) runs checks for relevant pull requests without deploying. Its deployment job is restricted to qualifying pushes to `main`, after the validation job succeeds. A separate [metrics workflow](.github/workflows/metrics.yml) generates repository reports.*

## Repository layout

| Path | Purpose |
| --- | --- |
| [`detections/`](detections/) | Version-controlled TOML detection definitions |
| [`development/`](development/) | Rule validation, conversion, Elastic synchronization, and auditd/health utilities |
| [`tests/`](tests/) | Test harnesses, unit tests, and sample events |
| [`.github/workflows/`](.github/workflows/) | CI, deployment, and reporting automation |
| [`metrics/`](metrics/) | Generated rule catalog, summaries, and ATT&CK Navigator layer |
| [`reports/`](reports/) | Example output from detection-health and auditd reporting |
| [`docs/`](docs/) | Design notes and implementation plans; plans do not necessarily indicate completed functionality |

## Running local validation

**Requirements:** Python 3.11+ and internet access for the ATT&CK reference check.

```bash
python -m pip install requests
python development/validation1.py
python development/mitre.py
python tests/run_detection_tests.py
```

The first script checks TOML rule structure; the second compares mappings with MITRE CTI data. The third tests selected rules against **simulated Python matchers** and positive/negative fixtures; it does **not** parse KQL, run Elastic detections, or validate live log ingestion.

The repository also contains Python unit tests for certain supporting modules. Deployment requires an authorized Elastic lab environment and its `ELASTIC_KEY` GitHub Actions secret. **Do not enable deployment against a shared or production environment without reviewing configuration and API permissions.**

## Detection health

The [sample detection-health report](reports/detection_health_summary.md) covers rule inventory, execution states, retained alert counts, and potential duplicate names. It deliberately separates **a rule running successfully** from **a rule reliably detecting attacker behavior**: zero alerts may reflect legitimate inactivity, missing telemetry, a narrow rule, or other conditions.

## Planned improvements

- Validate actual KQL behavior against representative Elastic event data rather than relying only on simulated fixture checks.
- Review placeholder detection names and verify source datasets match index patterns.
- Expand positive, negative, and edge-case tests to more rules.
- Move environment-specific URLs and settings into configuration before publishing the repo.
- Review reports, sample data, commit history, and credentials exposure before considering public visibility.

**Maintainer:** [hextrace80](https://github.com/hextrace80)
