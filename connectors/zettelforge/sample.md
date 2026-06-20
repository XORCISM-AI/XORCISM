# APT28 spear-phishing campaign targeting logistics sector

On 2026-06-12 our analysts observed **Fancy Bear** (aka Sofacy / STRONTIUM) running a
spear-phishing campaign against EU logistics providers. The lure exploited
CVE-2023-23397 (Outlook elevation of privilege) and dropped a Cobalt Strike beacon.

Observed TTPs:
- Initial access via phishing link (T1566.002)
- Credential dumping with Mimikatz (T1003.001)
- Lateral movement over SMB/Windows admin shares (T1021.002)
- C2 over HTTPS to 185[.]225[.]17[.]44 and beacon[.]example-evil[.]com

Indicators of compromise:
- IP: 185[.]225[.]17[.]44
- Domain: beacon[.]example-evil[.]com
- URL: hxxps://beacon[.]example-evil[.]com/jquery.min.js
- SHA256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
- Sender: invoices@logistics-update[.]net

Follow-up note: this overlaps with prior **Cozy Bear** (APT29) infrastructure reuse and
also references CVE-2024-21413. Tooling included AnyDesk and Rclone for exfiltration (T1567).
