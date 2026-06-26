"""run.py -- XORCISM connector for CrowdStrike Falcon (EDR/XDR endpoint detections).

Normalizes a Falcon detections/alerts export (Falcon API `/detects` or `/alerts`) into XORCISM
security alerts (XINCIDENT.ALERT via runner.import_incidents), with the impacted endpoint linked as an
ASSET. Parsing is delegated to the shared connectors/_edr.py normalizer. Offline: pass `file`, or run
the bundled sample. Worker-safe: stdlib only, secrets via env, ASCII-only output, no DB access.
"""
from __future__ import annotations

import os
import sys
from typing import Any, Dict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _edr import run_edr, smoke  # noqa: E402

SOURCE = "CrowdStrike Falcon"
LIST_KEYS = ["resources", "detections", "data"]
M = {
    "id": ["detection_id", "composite_id", "id"],
    "name": ["display_name", "name", "description"],
    "host": ["device.hostname", "hostname", "device_hostname"],
    "sev": ["max_severity", "severity", "severity_name", "max_severity_displayname"],
    "status": ["status"],
    "tactic": ["tactic", "tactic_id"],
    "technique": ["technique", "technique_id"],
    "desc": ["description", "cmdline"],
    "time": ["created_timestamp", "timestamp"],
}


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    return run_edr(params, os.path.dirname(os.path.abspath(__file__)), "sample.json", SOURCE, LIST_KEYS, M)


if __name__ == "__main__":
    smoke(run, SOURCE)
