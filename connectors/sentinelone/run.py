"""run.py -- XORCISM connector for SentinelOne (Singularity EDR/XDR) threats.

Normalizes a SentinelOne threats export (Singularity API `/web/api/v2.1/threats`) into XORCISM security
alerts (XINCIDENT.ALERT via runner.import_incidents), with the impacted endpoint linked as an ASSET.
Parsing is delegated to the shared connectors/_edr.py normalizer (confidence level malicious/suspicious
maps to high/medium). Offline: pass `file`, or run the bundled sample. Worker-safe: stdlib only.
"""
from __future__ import annotations

import os
import sys
from typing import Any, Dict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _edr import run_edr, smoke  # noqa: E402

SOURCE = "SentinelOne"
LIST_KEYS = ["data", "threats", "alerts"]
M = {
    "id": ["id", "threatInfo.threatId"],
    "name": ["threatInfo.threatName", "agentDetectionInfo.threatName", "threatName"],
    "host": ["agentRealtimeInfo.agentComputerName", "agentComputerName"],
    "sev": ["threatInfo.confidenceLevel", "threatInfo.analystVerdict", "confidenceLevel", "severity"],
    "status": ["threatInfo.mitigationStatus", "mitigationStatus", "status"],
    "tactic": ["threatInfo.classification", "classification"],
    "technique": ["threatInfo.mitreTactic", "indicators"],
    "desc": ["threatInfo.threatName"],
    "time": ["threatInfo.createdAt", "createdAt"],
}


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    return run_edr(params, os.path.dirname(os.path.abspath(__file__)), "sample.json", SOURCE, LIST_KEYS, M)


if __name__ == "__main__":
    smoke(run, SOURCE)
