# Detection Health Dashboard Publishing Design

## Purpose

Automate read-only Elastic detection-health collection and publish the existing
static dashboard through GitHub Pages without changing detection deployment.

## Scope and safety boundaries

- One dedicated workflow: `.github/workflows/detection_health_dashboard.yml`.
- Scheduled runs use live collection at 09:00 `America/New_York`.
- Manual runs choose `live` or `demo`; demo is the only mode that may publish
  the saved October 19 historical snapshot without Elastic credentials.
- Pull requests always build from the saved historical snapshot, run tests,
  and upload an artifact. They never receive Elastic secrets or deploy Pages.
- Scheduled and manual Pages deployment is limited to `main`.
- A live collection failure fails the build before the Pages artifact/deploy
  jobs. GitHub Pages keeps its previous successful deployment unchanged.
- The browser receives only sanitized rule metadata and aggregate health data.
  It receives no Elastic endpoints, credentials, raw events, host identifiers,
  or alert documents.
- Do not modify detection TOMLs, `elastic_sync.yml`, deployment scripts, or
  repository visibility. Do not commit, push, merge, run a workflow, or deploy
  Pages during this implementation.

## Workflow design

The workflow has a `build` job and a `deploy` job.

`build` has `contents: read` only. It chooses the input mode:

- `pull_request` -> `demo`;
- `schedule` -> `live`;
- `workflow_dispatch` -> the selected `mode` input.

It runs the existing dashboard tests. In live mode only, the collection step
receives `ELASTIC_HEALTH_KEY`, `ELASTIC_KIBANA_URL`, `ELASTICSEARCH_URL`, and
`ELASTIC_SECURITY_SPACE` from GitHub Actions secrets. `detection_health.py`
must exit successfully before dashboard generation continues. In demo mode,
the existing structured historical snapshot is used instead.

The generator writes a temporary `_site` directory containing `index.html`,
the CSS asset, and the JavaScript asset. It validates the site's exact file
structure and rejects credential/endpoint markers. The build job uploads the
directory with `actions/upload-pages-artifact`.

`deploy` depends on `build`; it runs only for scheduled or manual runs whose
ref is `refs/heads/main`. It has only `pages: write` and `id-token: write`,
uses the `github-pages` environment, invokes `actions/configure-pages`, then
deploys the previously uploaded artifact with `actions/deploy-pages`.

## Generator changes

`build_detection_health_dashboard.py` gains a `--site-directory` option. It
does not alter Phase 1 report output. When specified, it writes only:

- `index.html`;
- `detection_health_dashboard.css`;
- `detection_health_dashboard.js`.

The health snapshot remains embedded in the HTML using the existing safe JSON
encoding. The raw JSON file is intentionally not published. A standard-library
validation function checks the exact site asset set and rejects known sensitive
configuration markers before Pages upload.

## Tests and documentation

Extend dashboard tests for Pages output, validation, and sensitive-marker
rejection. Extend health tests to confirm missing live configuration fails
before requests. Add workflow-focused tests using standard-library text checks
for PR secret isolation, main-only Pages deployment, live/demo mode handling,
and deployment-pipeline independence.

README documents triggers, secrets, GitHub Pages configuration, live/demo
modes, the delayed-schedule caveat, and the difference between dashboard
publishing and detection deployment.

## Branch and PR sequencing

This branch starts from committed Phase 1. The final Phase 2 pull request must
target `main` only after Phase 1 has been merged into `main`; otherwise it
would include Phase 1 commits again. No merge is performed here.
