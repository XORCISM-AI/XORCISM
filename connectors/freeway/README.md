# Freeway connector

Imports a [**Freeway**](https://github.com/FLOCK4H/Freeway) (FLOCK4H — a Python/scapy Wi-Fi
penetration-testing suite) session export into the XORCISM **Wi-Fi pentest** module
([`/wifi-pentest`](../../xorcism_ts/server/wifipentest.ts), `XORCISM.WIFINETWORK` via
`runner.import_wifi`).

Freeway does monitor-mode discovery, deauth, beacon flood, fuzzing, evil-twin and captures
**PMKIDs / 4-way handshakes** (hashcat-crackable) to `/caps`. This connector ingests the **networks
it discovered** (flagging any AP it captured a handshake/PMKID for — that WPA2 PSK is now
offline-crackable) and feeds them to `/wifi-pentest`, which grades each network **A–F**, maps the
weaknesses to ATT&CK, and lists the toolkit (Aircrack-ng, hcxtools, Reaver, EAPHammer, **Freeway**…).
The connector **ingests Freeway output — it does not run Freeway**.

## Input (`file`, else bundled `sample.json`)

1. **Freeway export JSON**

   ```json
   { "networks": [ { "ssid": "HomeFiber", "bssid": "b4:fb:e4:11:22:33", "channel": "36",
                     "signal": -48, "enc": "WPA2", "cipher": "CCMP", "wps": true } ],
     "captures": [ { "type": "PMKID", "bssid": "b4:fb:e4:11:22:33", "ssid": "HomeFiber" } ] }
   ```

   (a bare list of network dicts is also accepted; `signal` may be dBm (negative) or a percentage).

2. **A text / CSV monitor dump** — one network per line:
   `<BSSID>  <SSID>  <channel>  <signal>  <encryption>` (whitespace- or comma-separated).

## Output → `XORCISM.WIFINETWORK`

```json
{ "source": "Freeway", "wifi": { "source": "freeway",
    "networks": [ { "ssid", "bssid", "channel", "signal", "enc", "cipher", "wps", "radio" } ] } }
```

`import_wifi` upserts each network by `BSSID` (per tenant) and stores the **raw** observation;
`Grade` / `RiskScore` / `Severity` are left `NULL` on purpose — `wifipentest.ts` is the single source
of truth and **grades the rows on read** (so Freeway-imported networks score identically to a live
`netsh`/`nmcli` scan). The imported networks then appear in the `/wifi-pentest` worklist.

> Note: the PMKID/handshake **captures** themselves (the crackable material in `/caps`) are not
> imported — they are cracked offline (hashcat/hcxtools). The connector flags which networks were
> captured in the network's `enc` note.

## Modes

* **Offline** — `file=<export JSON | text dump>`, or no config → bundled `sample.json`.

Worker-safe: stdlib only, ASCII-only output, no database access.

## Quick test

```bash
python connectors/freeway/run.py
```
