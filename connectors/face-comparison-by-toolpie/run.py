"""run.py — XORCISM OSINT pivot connector: Face Comparison by Toolpie.

Image & Video Analysis OSINT tool from the OSINT Newsletter tools library.
Tool: https://tools.osintnewsletter.com/osint-tools/face-comparison-by-toolpie

Turns a `target` observable into a pivot — a deep-link into Face Comparison by Toolpie when it exposes
a stable query URL, otherwise a reference to the tool page — returned as an `intel`
record (-> XTHREAT.INTELEXCHANGE, idempotent by reference). Worker-safe: no DB
access here. The shared engine is connectors/_osint.py.
"""
from __future__ import annotations

import os
import sys
from typing import Any, Dict

# Make the shared engine (connectors/_osint.py) importable wherever this runs.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _osint import osint_run  # noqa: E402

SLUG = 'face-comparison-by-toolpie'
TOOL_NAME = 'Face Comparison by Toolpie'
TOOL_URL = 'https://tools.osintnewsletter.com/osint-tools/face-comparison-by-toolpie'
CATEGORY = 'Image & Video Analysis OSINT'


def run(params: Dict[str, Any], workdir: str = "") -> Dict[str, Any]:
    return osint_run(SLUG, TOOL_NAME, TOOL_URL, CATEGORY, params, workdir)


if __name__ == "__main__":
    import json as _json
    import tempfile

    print(_json.dumps(run({"target": "example.com"}, tempfile.mkdtemp()), indent=2))
