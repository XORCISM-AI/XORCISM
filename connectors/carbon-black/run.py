"""run.py -- XORCISM connector for VMware Carbon Black Cloud (EDR) alerts.

Normalizes a Carbon Black Cloud alerts export (CBC API /alerts/_search) into XORCISM security alerts
(XINCIDENT.ALERT via runner.import_incidents), with the impacted device linked as an ASSET. Parsing is
delegated to the shared connectors/_edr.py normalizer (severity is the CBC 1-10 scale). Offline: pass
`file`, or run the bundled sample. Worker-safe: stdlib only, secrets via env, ASCII-only output.
"""
from __future__ import annotations

import os
import sys
from typing import Any, Dict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _edr import run_edr, smoke  # noqa: E402

SOURCE = "VMware Carbon Black"
LIST_KEYS = ["results", "alerts", "data"]
M = {
    "id": ["id", "legacy_alert_id"],
    "name": ["reason", "threat_cause_reason", "report_name", "reason_code"],
    "host": ["device_name", "deviceName"],
    "sev": ["severity"],
    "status": ["workflow.state", "workflow_state", "status"],
    "tactic": ["category", "type", "threat_cause_threat_category"],
    "technique": ["ttps", "threat_indicators"],
    "desc": ["reason"],
    "time": ["last_update_time", "create_time", "first_event_time"],
}


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    return run_edr(params, os.path.dirname(os.path.abspath(__file__)), "sample.json", SOURCE, LIST_KEYS, M)


if __name__ == "__main__":
    smoke(run, SOURCE)
