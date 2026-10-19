# Detection Health & Metrics Audit Report

Generated: 2026-10-19T03:19:56.004046Z
Alert lookback: `now-30d`

## Rule inventory

| Metric | Count |
| --- | ---: |
| Total deployed rules | 27 |
| Enabled | 26 |
| Disabled | 1 |
| Healthy | 26 |
| Failed | 0 |
| Degraded | 0 |
| Stale | 0 |
| Unknown | 0 |
| Not Yet Executed | 0 |

## Operational health

Operational health rate: **100.0%** (26 HEALTHY enabled rules / 26 enabled rules).
Disabled rules are excluded from this rate.

## Alert activity

Enabled rules with one or more recorded alerts: **6 of 26 (23.1%)**.
Total alerts in selected lookback: **52**.

### Top five rules by alert volume

| Rule name | Elastic internal UUID | Alerts | Most recent alert |
| --- | --- | ---: | --- |
| Endpoint Security (Elastic Defend) | `9a25b826-e6ce-47db-a9dc-5c47b3fed596` | 43 | 2026-10-16T19:58:42.216Z |
| Scheduled Task Creation via Schtasks | `011594fb-3521-4284-8734-318305dc8e10` | 4 | 2026-10-16T20:29:39.203Z |
| PowerShell Invoke-webRequest Downloading BAT file | `9286d464-2285-4c0b-ac24-f4eb5d6c783d` | 2 | 2026-10-12T03:48:31.040Z |
| AWS IAM Access Key Created | `9785b42e-835b-4c67-adfa-741cfee2fabf` | 1 | 2026-10-17T02:12:34.885Z |
| Excessive web traffic | `596f451d-c0af-4bbf-a77d-a18f012bfc73` | 1 | 2026-10-11T22:18:11.223Z |

### Enabled rules with zero alerts in the selected lookback

- Bat files observed in HTTP traffic (`d090a8d4-4fb8-4ed5-8696-fe0d2b518651`)
- Bat files observed in HTTP Traffic on Unusual Port  (`e21e7822-1e6f-4a9e-85f0-1ef795a7148a`)
- Data Archive for Potential Exfil (`c4eee38e-d815-4cdb-88c1-e5e653ddc6a1`)
- Data Archive for Potential Exfil (`cd5ff43c-8d9b-4a9a-bcfd-191a076eee36`)
- Excessive Web Traffic (`0caa8056-707b-40e4-ae8e-d75a14fb04c4`)
- Excessive Web Traffic (`6902657e-45ea-4df6-8342-a009a953267e`)
- John Ndukwe Test Rule (`613147c9-a8dd-46aa-b313-4ee96831f0ce`)
- new alert (`d140e260-8475-4c55-9fd0-754c2d3f373b`)
- Potential MSF PowerShell Payload Observed (`6380419e-81af-45a0-991f-51f19c7df05b`)
- Potential MSF PowerShell Payload Observed (`c722c41d-7d90-4db2-8975-d23ccd5db5d8`)
- Powershell execution via BAT file (`95c7ccb5-7274-4c7a-a0a1-10b74eb35407`)
- PowerShell Invoke-WebRequest Downloading .BAT File (`1453bcc4-40ab-4956-8bd8-9943d53bb942`)
- Suspicious File added to registry (`6a92daec-f19e-42e2-bf4f-06ac46af42d4`)
- Suspicious File Added to Registry (`c34afae9-a1ec-4741-871e-577d00fea8ab`)
- Suspicious file written to temp (`8af23407-7b18-4a1b-b035-f2062b47c147`)
- Suspicious File Written to Temp Directory (`2a36ab21-8e53-42e4-82c3-64359514020b`)
- Test Alert (`84704361-66a7-48d8-9a56-2a397e1e4082`)
- Test Alert (`af241a90-7f2c-4296-8cd7-8c64f464ae5d`)
- Web scanner activity -nmap and Nikto (`6b41e238-72e6-4fb0-bcd5-8de58773f39f`)
- Web scanner activity -nmap and Nikto (`e24b1105-1552-4928-96b3-9fbd9ff31d57`)

## Potential duplicate rules by name

- Candidate: **Data Archive for Potential Exfil**
  - `c4eee38e-d815-4cdb-88c1-e5e653ddc6a1` — stable rule_id: `00000000-0000-0000-0000-000000000004`
  - `cd5ff43c-8d9b-4a9a-bcfd-191a076eee36` — stable rule_id: `00000000-0000-0000-0000-000000000002`
- Candidate: **Test Alert**
  - `84704361-66a7-48d8-9a56-2a397e1e4082` — stable rule_id: `00000000-0000-0000-0000-000000000054`
  - `af241a90-7f2c-4296-8cd7-8c64f464ae5d` — stable rule_id: `00000000-0000-0000-0000-000000000024`
- Candidate: **Excessive Web Traffic**
  - `0caa8056-707b-40e4-ae8e-d75a14fb04c4` — stable rule_id: `00000000-0000-0000-0000-000000000005`
  - `596f451d-c0af-4bbf-a77d-a18f012bfc73` — stable rule_id: `7f2ba9d1-0bad-42b3-8634-f0f97d70444e`
  - `6902657e-45ea-4df6-8342-a009a953267e` — stable rule_id: `00000000-0000-0000-0000-000000000055`
- Candidate: **Web scanner activity -nmap and Nikto**
  - `6b41e238-72e6-4fb0-bcd5-8de58773f39f` — stable rule_id: `00000000-0000-0000-0000-000000000003`
  - `e24b1105-1552-4928-96b3-9fbd9ff31d57` — stable rule_id: `00000000-0000-0000-0000-000000000006`
- Candidate: **Suspicious File Added to Registry**
  - `6a92daec-f19e-42e2-bf4f-06ac46af42d4` — stable rule_id: `92bcbfbb-ad2b-4de3-88fe-1e59b4f71577`
  - `c34afae9-a1ec-4741-871e-577d00fea8ab` — stable rule_id: `00000000-0000-0000-0000-000000000008`
- Candidate: **Potential MSF PowerShell Payload Observed**
  - `6380419e-81af-45a0-991f-51f19c7df05b` — stable rule_id: `00000000-0000-0000-0000-000000000045`
  - `c722c41d-7d90-4db2-8975-d23ccd5db5d8` — stable rule_id: `ffea60b4-b6c2-4996-8597-67516d6bab65`
These are candidates for investigation, not confirmed duplicates.

## Findings and recommended follow-up actions

- Review Bat files observed in HTTP traffic (`d090a8d4-4fb8-4ed5-8696-fe0d2b518651`): ZERO_ALERTS_IN_LOOKBACK.
- Review Bat files observed in HTTP Traffic on Unusual Port  (`e21e7822-1e6f-4a9e-85f0-1ef795a7148a`): ZERO_ALERTS_IN_LOOKBACK.
- Review Data Archive for Potential Exfil (`c4eee38e-d815-4cdb-88c1-e5e653ddc6a1`): ZERO_ALERTS_IN_LOOKBACK.
- Review Data Archive for Potential Exfil (`cd5ff43c-8d9b-4a9a-bcfd-191a076eee36`): ZERO_ALERTS_IN_LOOKBACK.
- Review Excessive Web Traffic (`0caa8056-707b-40e4-ae8e-d75a14fb04c4`): ZERO_ALERTS_IN_LOOKBACK.
- Review Excessive Web Traffic (`6902657e-45ea-4df6-8342-a009a953267e`): ZERO_ALERTS_IN_LOOKBACK.
- Review John Ndukwe Test Rule (`613147c9-a8dd-46aa-b313-4ee96831f0ce`): ZERO_ALERTS_IN_LOOKBACK.
- Review MsBuild Making Network Connections (`b9a6435d-1df9-4c2e-bbbe-f5ac47e6a673`): DISABLED.
- Review new alert (`d140e260-8475-4c55-9fd0-754c2d3f373b`): ZERO_ALERTS_IN_LOOKBACK.
- Review Potential MSF PowerShell Payload Observed (`6380419e-81af-45a0-991f-51f19c7df05b`): ZERO_ALERTS_IN_LOOKBACK.
- Review Potential MSF PowerShell Payload Observed (`c722c41d-7d90-4db2-8975-d23ccd5db5d8`): ZERO_ALERTS_IN_LOOKBACK.
- Review Powershell execution via BAT file (`95c7ccb5-7274-4c7a-a0a1-10b74eb35407`): ZERO_ALERTS_IN_LOOKBACK.
- Review PowerShell Invoke-WebRequest Downloading .BAT File (`1453bcc4-40ab-4956-8bd8-9943d53bb942`): ZERO_ALERTS_IN_LOOKBACK.
- Review Suspicious File added to registry (`6a92daec-f19e-42e2-bf4f-06ac46af42d4`): ZERO_ALERTS_IN_LOOKBACK.
- Review Suspicious File Added to Registry (`c34afae9-a1ec-4741-871e-577d00fea8ab`): ZERO_ALERTS_IN_LOOKBACK.
- Review Suspicious file written to temp (`8af23407-7b18-4a1b-b035-f2062b47c147`): ZERO_ALERTS_IN_LOOKBACK.
- Review Suspicious File Written to Temp Directory (`2a36ab21-8e53-42e4-82c3-64359514020b`): ZERO_ALERTS_IN_LOOKBACK.
- Review Test Alert (`84704361-66a7-48d8-9a56-2a397e1e4082`): ZERO_ALERTS_IN_LOOKBACK.
- Review Test Alert (`af241a90-7f2c-4296-8cd7-8c64f464ae5d`): ZERO_ALERTS_IN_LOOKBACK.
- Review Web scanner activity -nmap and Nikto (`6b41e238-72e6-4fb0-bcd5-8de58773f39f`): ZERO_ALERTS_IN_LOOKBACK.
- Review Web scanner activity -nmap and Nikto (`e24b1105-1552-4928-96b3-9fbd9ff31d57`): ZERO_ALERTS_IN_LOOKBACK.
- Investigate FAILED, DEGRADED, STALE, or UNKNOWN execution states before relying on the affected detection.
- Review disabled rules to confirm they are intentionally inactive.
- Treat zero alerts in the selected lookback as a review prompt for telemetry coverage, rule scope, and expected activity—not proof of a bad rule.

## Methodology and limitations

This report lists deployed Elastic Security rules from Kibana and aggregates alert documents by Elastic internal rule UUID over the selected lookback.
A successful execution means the rule most recently ran successfully; it does not prove that the rule searched complete telemetry, matched intended behavior, or detected every relevant event.
Recorded alert activity reflects alerts retained and returned for the selected lookback. Zero alerts do not establish that a rule has never alerted or that it is ineffective.
Potential duplicate names are normalized for comparison and remain investigation candidates because distinct rules can intentionally share a name.
