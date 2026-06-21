"""ressrf connector — run the SSRF scanner against an in-scope target and import confirmed findings.

ressrf takes a target LIST and writes to an output DIRECTORY, so this is an import-type connector that
writes the (scope-validated) target to a temp file, runs ressrf, and parses output/findings.txt into
VULNERABILITY links. Returns {"assets": [...], "vulns": [...], "source": "ressrf"}.
"""
import hashlib
import os
import re
import subprocess
from urllib.parse import urlparse


def run(params, workdir):
    target = str(params.get("target") or "").strip()
    if not target:
        raise RuntimeError("ressrf: target required")
    tfile = os.path.join(workdir, "targets.txt")
    with open(tfile, "w", encoding="utf-8") as fh:
        fh.write(target + "\n")
    argv = ["ressrf", "-l", tfile, "-o", workdir, "-s"]
    if params.get("collab"):
        argv += ["-c", str(params["collab"])]
    if params.get("rate"):
        argv += ["-r", str(int(params["rate"]))]
    try:
        subprocess.run(argv, capture_output=True, text=True, timeout=1800)
    except FileNotFoundError:
        raise RuntimeError("ressrf binary not found — install it: https://github.com/R0X4R/ressrf")

    host = urlparse(target if "://" in target else "http://" + target).hostname or target
    assets = [{"key": host, "hostname": host}]
    vulns = []
    findings_path = os.path.join(workdir, "findings.txt")
    if os.path.exists(findings_path):
        with open(findings_path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                tags = re.findall(r"\[([^\]]+)\]", line)
                url = line.split(" ", 1)[0]
                ref = "ressrf:" + hashlib.sha1(line.encode("utf-8")).hexdigest()[:16]
                label = " / ".join(tags) if tags else "confirmed"
                vulns.append({"asset": host, "ref": ref, "severity": "High", "name": f"SSRF ({label}) @ {url}"})
    return {"assets": assets, "vulns": vulns, "source": "ressrf"}
