# Detection Engineering

[![Detection validation and deployment](https://github.com/jndukwe8080/detection-engineering/actions/workflows/elastic_sync.yml/badge.svg)](https://github.com/jndukwe8080/detection-engineering/actions/workflows/elastic_sync.yml)

[![TOML/MITRE validation](https://github.com/jndukwe8080/detection-engineering/actions/workflows/toml_mitre_validation.yml/badge.svg)](https://github.com/jndukwe8080/detection-engineering/actions/workflows/toml_mitre_validation.yml)

This is an independent Elastic Security detection-engineering lab. It is not a
production SOC environment.

## Detection Health Dashboard

The static Detection Health Dashboard combines repository-managed TOML metadata
with a Detection Health & Metrics Audit snapshot. It is designed to make four
separate dimensions visible:

- **Deployment state:** whether an Elastic rule is represented in the snapshot
  and whether it is enabled.
- **Operational health:** execution status and freshness reported by Elastic.
- **Alert activity:** recorded alerts in the selected lookback window.
- **Validation health:** whether a repository rule is registered in the offline
  fixture manifest. This does not claim a stored test execution result.

The dashboard does **not** measure true-positive rate, false-positive rate, or
overall detection effectiveness. Those require real, labeled investigation
outcomes. A successful rule execution does not prove coverage or effectiveness,
and zero alerts are a review opportunity rather than an unhealthy rule.

### Historical snapshot and freshness

The initial dashboard is generated entirely offline from the saved October 19
CSV and Markdown health reports. It labels itself as a historical snapshot and
calculates its age in the browser from the original report timestamp. It must
never be presented as live data.

The generated dashboard contains no Elastic endpoint, API key, authorization
header, or raw alert document. Browser JavaScript uses `textContent` rather
than `innerHTML` for rule metadata, and the embedded JSON escapes characters
that could terminate its data script element.

### Generate locally from saved reports

From the repository root in PowerShell:

```powershell
python development/build_detection_health_dashboard.py --from-legacy-reports --reports-directory reports
```

This converts `reports/detection_health_inventory.csv` and
`reports/detection_health_summary.md` into
`reports/detection_health_snapshot.json`, then writes:

- `reports/detection_health_dashboard.html`
- `reports/detection_health_dashboard.css`
- `reports/detection_health_dashboard.js`

To rebuild from an existing structured snapshot instead:

```powershell
python development/build_detection_health_dashboard.py --snapshot reports/detection_health_snapshot.json --reports-directory reports
```

To view locally, use a simple local web server so the browser loads the CSS and
JavaScript assets reliably:

```powershell
python -m http.server 8000 --directory reports
```

Then open [http://localhost:8000/detection_health_dashboard.html](http://localhost:8000/detection_health_dashboard.html).
Stop the local server with `Ctrl+C` when finished.

### Run local tests

```powershell
python -m unittest tests/test_detection_health.py tests/test_detection_health_dashboard.py
python tests/run_detection_tests.py
python tests/test_update_alert.py
```

The fixture runner uses temporary Python matchers that approximate selected
queries. It does not execute Elastic KQL and does not prove live alert
generation.

### Live health collection (read-only)

The existing health collector is read-only and now reads configuration only
from environment variables. It requires a dedicated, restricted health API key
and never writes to Elastic:

```powershell
$env:ELASTIC_HEALTH_KEY = "<read-only-api-key>"
$env:ELASTIC_KIBANA_URL = "https://<deployment>.kb.<region>.elastic.cloud"
$env:ELASTICSEARCH_URL = "https://<deployment>.es.<region>.elastic.cloud"
$env:ELASTIC_SECURITY_SPACE = "default"
python development/detection_health.py
```

Do not put these values in source files, reports, or browser assets. If an
alert aggregation request is unavailable or incomplete, the collector preserves
prior complete reports instead of replacing them with zero-alert data.

### Publishing

No dashboard publishing workflow is configured in this local implementation.
Future GitHub Pages or artifact publishing must be a separate, authorized
main-branch workflow with no Elastic deployment credentials. Pull-request
validation must never deploy rules to Elastic.
