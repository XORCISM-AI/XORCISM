# Rulezet connector (detection-rule search)

Searches [Rulezet](https://rulezet.org) — the open-source repository of **~197k community detection
rules** (YARA, Sigma, Suricata, Zeek, CRS, Nova, Wazuh, Elastic) covering **858+ ATT&CK techniques** —
and imports the matches into XORCISM's detection-content stores. Turn a CVE on your assets, or an ATT&CK
technique an adversary uses, into ready-to-deploy detections.

## Search modes
| Param | What it finds | Endpoint |
|---|---|---|
| `cve=CVE-2020-27130` | rules linked to a CVE | CIRCL Vulnerability-Lookup proxy `GET /api/rulezet/search_rules_by_vulnerabilities/<cve>` |
| `technique=T1059` | rules for an ATT&CK technique (attack-chain step) | `rulezet.org/api` rule search |
| `query=cobalt strike` | free-text rule search | `rulezet.org/api` rule search |
| `file=<path>` | parse a saved Rulezet JSON response offline | — |

## Mapping
- **Sigma** (and Suricata / Zeek / CRS / Nova / Wazuh / Elastic) → `XTHREAT.SIGMARULE`
  (`runner.import_sigma_rules`), the format in `LogSource`.
- **YARA** → `XTHREAT.YARARULE` (`runner.import_yara_rules`).
- Both idempotent by the rule reference; the rule's **ATT&CK techniques** are kept as tags — so imported
  rules light up **Threat-Informed Defense** and **Purple-Team** detection coverage.

## Usage
```bash
python run.py                                   # bundled sample (CVE-2020-27130 rules)
python run.py  # params: {"cve":"CVE-2020-27130"}     -> detection rules for a CVE
python run.py  # params: {"technique":"T1059"}        -> rules for an ATT&CK technique
python run.py  # params: {"query":"cobalt strike"}    -> free-text rule search
```
Public API (no auth; optional `RULEZET_TOKEN`). Worker-safe: stdlib `urllib` only, ASCII-only output,
no DB access. Returns `{source:"Rulezet", sigma:[...], yara:[...]}`.
