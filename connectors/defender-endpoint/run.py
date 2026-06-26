"""run.py -- XORCISM connector for Microsoft Defender for Endpoint (MDE) EDR alerts.

Normalizes an MDE alerts export (Defender API / Graph security `/alerts`) into XORCISM security alerts
(XINCIDENT.ALERT via runner.import_incidents), with the impacted device linked as an ASSET. Parsing is
delegated to the shared connectors/_edr.py normalizer. Offline: pass `file`, or run the bundled sample.
Worker-safe: stdlib only, secrets via env, ASCII-only output, no DB access.
"""
from __future__ import annotations

import os
import sys
from typing import Any, Dict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _edr import run_edr, smoke  # noqa: E402

SOURCE = "Microsoft Defender for Endpoint"
LIST_KEYS = ["value", "alerts", "data"]
M = {
    "id": ["id", "alertId"],
    "name": ["title", "name"],
    "host": ["computerDnsName", "deviceDnsName", "machineId"],
    "sev": ["severity"],
    "status": ["status"],
    "tactic": ["category", "mitreTactics"],
    "technique": ["techniques", "mitreTechniques"],
    "desc": ["description"],
    "time": ["alertCreationTime", "firstEventTime"],
}


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    return run_edr(params, os.path.dirname(os.path.abspath(__file__)), "sample.json", SOURCE, LIST_KEYS, M)


if __name__ == "__main__":
    smoke(run, SOURCE)
