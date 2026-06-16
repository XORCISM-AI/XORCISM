"""
provider_nessus.py - Converted from XProviderNessus/Program.cs
Jerome Athias - XORCISM

Parses Nessus scan output (.nessus XML files) and stores findings
in XORCISM.db (SCAN, SCANRESULT, VULNERABILITY tables).

Usage:
    python provider_nessus.py --nessus scan.nessus [--scan-name "My Scan"]
"""

import argparse
import os
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from xorcism_python.models.base import session_scope
from xorcism_python.utils import log

MODULE = "ProviderNessus"


def _text(el: Optional[ET.Element]) -> str:
    if el is None:
        return ""
    return "".join(el.itertext()).strip()


def _plugin_attr(item: ET.Element, attr: str) -> str:
    el = item.find(attr)
    return _text(el)


def parse_nessus(xml_path: str, scan_name: Optional[str] = None) -> None:
    log(MODULE, f"Parsing Nessus file: {xml_path}")
    tree = ET.parse(xml_path)
    root = tree.getroot()

    scan_label = scan_name or os.path.basename(xml_path)
    now_str = datetime.now(timezone.utc).isoformat()

    scan_results = 0

    with session_scope("XORCISM") as session:
        from xorcism_python.models.xorcism import SCAN, SCANRESULT, HOST

        # Create a SCAN record
        scan = SCAN(
            SCANName=scan_label[:255],
            SCANDate=now_str,
            SCANType="Nessus",
        )
        session.add(scan)
        session.flush()   # get SCANid

        for report_host in root.findall(".//ReportHost"):
            host_name = report_host.get("name", "")
            ip = ""
            os_str = ""

            # Host properties
            for tag in report_host.findall("HostProperties/tag"):
                tag_name = tag.get("name", "")
                if tag_name == "host-ip":
                    ip = tag.text or ""
                elif tag_name == "operating-system":
                    os_str = tag.text or ""

            # Upsert HOST
            host = session.query(HOST).filter(HOST.HOSTIPAddress == ip).first()
            if host is None and ip:
                host = HOST(
                    HOSTName=host_name[:255],
                    HOSTIPAddress=ip[:50],
                    HOSTOS=os_str[:255] if os_str else None,
                )
                session.add(host)
                session.flush()

            # ReportItems = findings (vulnerabilities per plugin)
            for item in report_host.findall("ReportItem"):
                plugin_id   = item.get("pluginID", "")
                plugin_name = item.get("pluginName", "")
                severity    = item.get("severity", "0")
                port        = item.get("port", "0")
                protocol    = item.get("protocol", "")
                service     = item.get("svc_name", "")

                cve_ids  = [el.text for el in item.findall("cve") if el.text]
                cvss_score_str = _plugin_attr(item, "cvss3_base_score") or _plugin_attr(item, "cvss_base_score")
                description = _plugin_attr(item, "description")
                solution    = _plugin_attr(item, "solution")
                synopsis    = _plugin_attr(item, "synopsis")
                plugin_output = _plugin_attr(item, "plugin_output")

                # Map severity (0-4) to label
                severity_map = {
                    "0": "None", "1": "Low", "2": "Medium", "3": "High", "4": "Critical"
                }
                severity_label = severity_map.get(severity, "Unknown")

                result = SCANRESULT(
                    SCANid=scan.SCANid,
                    SCANRESULTHostName=host_name[:255] if host_name else None,
                    SCANRESULTIPAddress=ip[:50] if ip else None,
                    SCANRESULTPort=int(port) if port.isdigit() else None,
                    SCANRESULTProtocol=protocol[:20] if protocol else None,
                    SCANRESULTService=service[:100] if service else None,
                    SCANRESULTPluginID=plugin_id[:50] if plugin_id else None,
                    SCANRESULTPluginName=plugin_name[:255] if plugin_name else None,
                    SCANRESULTSeverity=severity_label[:50],
                    SCANRESULTCVSSScore=float(cvss_score_str) if cvss_score_str else None,
                    SCANRESULTDescription=description[:4000] if description else None,
                    SCANRESULTSolution=solution[:4000] if solution else None,
                    SCANRESULTSynopsis=synopsis[:2000] if synopsis else None,
                    SCANRESULTPluginOutput=plugin_output[:4000] if plugin_output else None,
                    SCANRESULTCVEList=",".join(cve_ids)[:1000] if cve_ids else None,
                )
                session.add(result)
                scan_results += 1

        session.commit()

    log(MODULE, f"Imported {scan_results} scan results from {xml_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Import Nessus .nessus file into XORCISM.db")
    parser.add_argument("--nessus", required=True, help="Path to .nessus XML file")
    parser.add_argument("--scan-name", default=None, help="Optional label for the scan")
    args = parser.parse_args()

    if not os.path.exists(args.nessus):
        print(f"ERROR: File not found: {args.nessus}", file=sys.stderr)
        sys.exit(1)

    parse_nessus(args.nessus, args.scan_name)


if __name__ == "__main__":
    main()
