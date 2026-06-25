"""run.py -- XORCISM connector for Freeway (github.com/FLOCK4H/Freeway).

Freeway is a Python/scapy Wi-Fi penetration-testing suite (monitor, deauth, beacon flood, fuzzing,
evil-twin, PMKID/4-way-handshake capture). This connector ingests a Freeway *session export* (the
networks/clients it discovered + any captures) and feeds the networks into the XORCISM Wi-Fi pentest
module (/wifi-pentest, XORCISM.WIFINETWORK via runner.import_wifi) where they are graded A-F. It does
not drive Freeway; it parses its output.

Accepted inputs (`file`, else bundled sample.json):
  * Freeway export JSON:
      {"networks":[{"ssid","bssid","channel","signal","enc"|"security","cipher","wps","clients"}],
       "captures":[{"type":"PMKID"|"handshake","bssid","ssid"}]}
    (also tolerates a bare list of network dicts), or
  * a text/CSV monitor dump -- one network per line:
      "<BSSID>  <SSID>  <channel>  <signal>  <encryption>"  (whitespace- or comma-separated).

Networks that had a PMKID / 4-way handshake captured are flagged (the WPA2 PSK is now offline-
crackable); that is carried in the network's `enc` note. Worker-safe: stdlib only, ASCII output.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List

SOURCE = "Freeway"
_MAC = re.compile(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})")
_ENC = re.compile(r"\b(WPA3|WPA2|WPA|WEP|OPEN|OPN|ESS)\b", re.I)


def _signal_pct(v: Any) -> Any:
    """Freeway reports RSSI in dBm (negative) or a percentage; normalize to 0-100 or None."""
    try:
        n = int(float(v))
    except (TypeError, ValueError):
        return None
    if n <= 0:  # dBm
        return max(0, min(100, 2 * (n + 100)))
    return max(0, min(100, n))


def _net(d: Dict[str, Any], captured: set) -> Dict[str, Any] | None:
    bssid = str(d.get("bssid") or d.get("mac") or "").strip().lower()
    if not _MAC.fullmatch(bssid or ""):
        return None
    enc = str(d.get("enc") or d.get("security") or d.get("encryption") or d.get("auth") or "")
    if enc.upper() in ("ESS", "OPN"):
        enc = "OPEN"
    if bssid in captured:
        enc = (enc + " [handshake/PMKID captured]").strip()
    return {
        "ssid": str(d.get("ssid") or d.get("essid") or "").strip(),
        "bssid": bssid,
        "channel": str(d.get("channel") or d.get("chan") or d.get("ch") or ""),
        "signal": _signal_pct(d.get("signal") if d.get("signal") is not None else d.get("rssi") or d.get("power")),
        "enc": enc,
        "cipher": str(d.get("cipher") or ""),
        "wps": d.get("wps"),
        "radio": str(d.get("radio") or ""),
    }


def _from_text(text: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for ln in text.splitlines():
        m = _MAC.search(ln)
        if not m:
            continue
        bssid = m.group(1).lower()
        rest = (ln[:m.start()] + " " + ln[m.end():]).replace(",", " ")
        toks = [t for t in rest.split() if t]
        enc_m = _ENC.search(ln)
        enc = enc_m.group(1).upper() if enc_m else ""
        if enc in ("ESS", "OPN"):
            enc = "OPEN"
        nums = [t for t in toks if re.fullmatch(r"-?\d+", t)]
        ssid = next((t for t in toks if not re.fullmatch(r"-?\d+", t) and not _ENC.fullmatch(t)), "")
        channel = nums[0] if nums else ""
        signal = _signal_pct(nums[1]) if len(nums) > 1 else None
        out.append({"ssid": ssid, "bssid": bssid, "channel": channel, "signal": signal, "enc": enc, "cipher": "", "wps": None, "radio": ""})
    return out


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    path = params.get("file") or os.path.join(os.path.dirname(__file__), "sample.json")
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        raw = fh.read()
    nets: List[Dict[str, Any]] = []
    try:
        data = json.loads(raw)
    except Exception:  # noqa: BLE001
        data = None
    if isinstance(data, dict):
        captured = set()
        for cap in data.get("captures") or []:
            b = str((cap or {}).get("bssid") or "").strip().lower()
            if b:
                captured.add(b)
        for d in data.get("networks") or data.get("aps") or []:
            n = _net(d, captured)
            if n:
                nets.append(n)
    elif isinstance(data, list):
        for d in data:
            if isinstance(d, dict):
                n = _net(d, set())
                if n:
                    nets.append(n)
    else:
        nets = _from_text(raw)

    # de-dupe by BSSID
    seen = set()
    uniq = []
    for n in nets:
        if n["bssid"] in seen:
            continue
        seen.add(n["bssid"])
        uniq.append(n)
    return {"source": SOURCE, "wifi": {"source": "freeway", "networks": uniq}}


if __name__ == "__main__":
    import tempfile
    r = run({}, tempfile.mkdtemp())
    nets = r["wifi"]["networks"]
    print("source=%s networks=%d" % (r["source"], len(nets)))
    for n in nets:
        print("  %-18s %s  ch=%s sig=%s  %s" % (n["ssid"] or "(hidden)", n["bssid"], n["channel"], n["signal"], n["enc"]))
