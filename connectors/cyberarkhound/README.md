# CyberArkHound connector

Imports a [CyberArkHound](https://github.com/jazofra/CyberArkHound) export into XORCISM. CyberArkHound is
**"BloodHound for CyberArk"** — a Go tool that exports CyberArk PVWA / Privilege Cloud data into a
BloodHound-compatible **OpenGraph JSON** of privilege-escalation and credential-access paths.

## Produce the export
```
./cyberarkhound --pvwa https://pvwa.example.com --username api_user --password $SECRET \
  --output export.json --target-domains corp.com \
  --include-applications --include-platforms --include-psm
```

## Mapping
- each graph node (safe / account / user / group / CCP AppID / PSM server) → **ASSET** (tags `cyberark` / `pam` / `identity` / `<kind>`)
- each attack-path edge → **VULN** on the target entity:
  - `CanGrantAccessTo` → high (ATT&CK **T1098**) · `CanHijackViaReconcile` → high (**T1187**)
  - `CanRetrieveViaCCP` → high (**T1528**, *critical* when the AppID is unrestricted) · `HasAccessTo` → medium (**T1555**)
  - `CanApprove` → medium (**T1098**) · `LinkedTo` → low (**T1555**) · `UsedAccount` → skipped (activity)
- misconfigurations → **VULN**: unrestricted CCP AppID, default AIMWebService, platform with wildcard `AllowedSafes`,
  safe without CPM rotation, PSM account without session monitoring; plus any top-level `findings[]`.

Severity is raised toward privileged targets (admin / domain admin / reconcile) and unrestricted CCP AppIDs.

## Run
- **Connector**: `python connectors/runner.py --connector cyberarkhound --file export.json`
- **Attack chain**: the **CyberArk PAM attack paths (CyberArkHound)** playbook (Tool-chaining / `/chain`) seeds
  `cyberarkhound` and escalates any finding to CyberSentinel AI for ATT&CK mapping. Simulate or live, under ROE.

`run.py` does no DB access (worker-safe). CyberArkHound reads a live vault — only use exports from an
**authorized** engagement.
