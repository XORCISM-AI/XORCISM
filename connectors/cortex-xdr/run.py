"""run.py -- XORCISM connector for Palo Alto Cortex XDR (EDR/XDR alerts).

Normalizes a Cortex XDR alerts export (XDR API `get_alerts` — alerts nested under reply.alerts.data)
into XORCISM security alerts (XINCIDENT.ALERT via runner.import_incidents), with the impacted endpoint
linked as an ASSET. Parsing is delegated to the shared connectors/_edr.py normalizer. Offline: pass
`file`, or run the bundled sample. Worker-safe: stdlib only, secrets via env, ASCII-only output.
"""
from __future__ import annotations

import os
import sys
from typing import Any, Dict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _edr import run_edr, smoke  # noqa: E402

SOURCE = "Cortex XDR"
LIST_KEYS = ["reply.alerts.data", "reply.alerts", "alerts", "data"]
M = {
    "id": ["alert_id", "internal_id", "id"],
    "name": ["name", "alert_name", "description"],
    "host": ["host_name", "endpoint_name", "hostname", "agent_hostname"],
    "sev": ["severity"],
    "status": ["status", "resolution_status"],
    "tactic": ["mitre_tactic_id_and_name", "mitre_tactics"],
    "technique": ["mitre_technique_id_and_name", "mitre_techniques"],
    "desc": ["description"],
    "time": ["detection_timestamp", "timestamp"],
}


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    return run_edr(params, os.path.dirname(os.path.abspath(__file__)), "sample.json", SOURCE, LIST_KEYS, M)


if __name__ == "__main__":
    smoke(run, SOURCE)
