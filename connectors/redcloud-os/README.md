# RedCloud-OS connector

Imports a [RedCloud-OS](https://github.com/RedCloudOS) cloud red-team engagement into XORCISM.
RedCloud-OS is a **"Cloud Adversary Simulation Operating System for Red Teams"** — a Linux distribution that
bundles the leading cloud attack tools across **AWS / Azure / GCP / Kubernetes** and organises them by
kill-chain phase (Enumeration · Initial Access · Credential Access · Privilege Escalation · Persistence ·
Defense Evasion · Lateral Movement · Exfiltration).

Bundled tools include **Pacu, ScoutSuite, Prowler, cloud_enum, CloudBrute, cloudfox, PMapper, heimdall,
AWeSomeUserFinder, whoAMI-scanner, AzureHound, Oh365UserFinder, ROADtools, gcp_scanner, GCPBucketBrute,
GCPTokenReuse, peirates, EKSHolmes, KubiScan, BloodHound and gitleaks**.

## Input — pass the engagement output as `file`

The connector **auto-detects** the format:

1. **RedCloud-OS engagement bundle** (recommended — aggregate your run):
   ```json
   {
     "engagement": "acme-aws-redteam-2026",
     "csp": "aws",
     "assets": [ {"name": "arn:aws:iam::111122223333:role/admin", "kind": "role", "csp": "aws"} ],
     "findings": [
       {"asset": "prod-bucket", "title": "S3 bucket public", "severity": "high",
        "csp": "aws", "phase": "Exfiltration", "tool": "ScoutSuite", "attck": "T1530",
        "description": "Bucket grants READ to AllUsers."}
     ]
   }
   ```
2. **ScoutSuite** — the `scoutsuite_results_<provider>-<account>.js`/`.json` results file (the `scoutsuite_results = …` JS prefix is stripped automatically).
3. **Prowler** — OCSF JSON or v3 JSON (a list of findings; `PASS`/`MANUAL` are skipped).
4. **BloodHound / AzureHound / PMapper / cloudfox graph** — `{nodes:[…], edges:[…]}` (privilege-escalation paths).

## Mapping
- each cloud resource / identity (account, role, user, bucket, VM, function, cluster, node) → **ASSET**
  (tags `redcloud` / `<csp>` / `cloud` / `<kind>`)
- each misconfiguration, exposure or attack-path edge → **VULN**, severity-ranked and **ATT&CK-tagged**:
  - exposure / public storage → **T1530** · MFA gaps → **T1556** · logging/monitoring disabled → **T1562**
  - IAM privilege-escalation / over-permissioned → **T1098** · unsecured credentials & secrets → **T1552**
  - public-facing exploit → **T1190** · valid-account / lateral movement → **T1078** · enumeration → **T1580**

Severity is raised toward privileged targets (admin / owner / `*:*` / AdministratorAccess). CSP is inferred
per finding (or forced with the `csp` parameter).

## Run
- **Connector**: `python connectors/runner.py --connector redcloud-os --file engagement.json`
- **Attack chain**: the **Cloud adversary simulation (RedCloud-OS)** playbook (Tool-chaining / `/chain`) seeds
  `redcloud-os` and escalates any finding to CyberSentinel AI for ATT&CK mapping — feeding exposure /
  attack-path / cloud-security views. Simulate or live, under ROE.

`run.py` does no live cloud or DB access (worker-safe). RedCloud-OS attacks real cloud tenants — only import
exports from an **authorized** engagement.
