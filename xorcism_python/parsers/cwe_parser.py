"""
cwe_parser.py - Converted from CWEParser/Program.cs
Jerome Athias - XORCISM

Parses the MITRE CWE XML catalog (cwec_v4.x.xml) and inserts records
into the XORCISM database (CWE, CWEWEAKNESS tables).

Usage:
    python cwe_parser.py --xml cwec_v4.0.xml [--db-dir /path/to/databases]

Original: System.Xml.XmlDocument / XmlNodeList
Converted to: xml.etree.ElementTree (stdlib, no extra deps)
"""

import argparse
import io
import os
import sys
import xml.etree.ElementTree as ET
import zipfile
from typing import Optional

import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from xorcism_python.models.base import session_scope
from xorcism_python.utils import log

MODULE = "CWEParser"

# MITRE publishes the CWE catalog as a zip containing a single XML file.
CWE_ZIP_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"


# ---------------------------------------------------------------------------
# Download helper
# ---------------------------------------------------------------------------

def download_cwe(dest: str) -> str:
    """
    Download the latest CWE XML catalog from MITRE and extract it.

    The file is published as a ZIP archive (cwec_latest.xml.zip) containing
    a single XML file named cwec_vX.Y.xml.

    Args:
        dest: Local path where the extracted XML file will be saved.
              If dest ends with '.zip', the XML is extracted next to it.
              Otherwise dest is used directly as the output XML path.

    Returns:
        The path to the extracted XML file.
    """
    log(MODULE, f"Downloading CWE catalog from {CWE_ZIP_URL}")

    resp = requests.get(CWE_ZIP_URL, timeout=120, stream=True)
    resp.raise_for_status()

    # Read zip from memory to avoid writing a temp zip to disk
    zip_data = io.BytesIO(resp.content)

    with zipfile.ZipFile(zip_data) as zf:
        # The archive contains exactly one XML file
        xml_names = [n for n in zf.namelist() if n.lower().endswith(".xml")]
        if not xml_names:
            raise RuntimeError("No XML file found inside the downloaded zip archive.")

        xml_name = xml_names[0]
        log(MODULE, f"Extracting {xml_name} -> {dest}")

        with zf.open(xml_name) as src, open(dest, "wb") as dst:
            dst.write(src.read())

    log(MODULE, f"CWE XML saved to {dest}")
    return dest


def ensure_cwe_xml(xml_path: str) -> str:
    """
    Return xml_path if the file already exists locally.
    Otherwise download it automatically from the MITRE website.

    Args:
        xml_path: Desired local path for the CWE XML file.

    Returns:
        Path to the (now guaranteed to exist) XML file.
    """
    if os.path.exists(xml_path):
        log(MODULE, f"Using existing CWE XML: {xml_path}")
        return xml_path

    log(MODULE, f"File not found locally ({xml_path}), downloading...")
    return download_cwe(xml_path)

# ---------------------------------------------------------------------------
# Namespace helpers
# ---------------------------------------------------------------------------

NS = {"cwe": "http://cwe.mitre.org/cwe-7"}   # namespace used in cwec_v4.x.xml


def _tag(name: str) -> str:
    return f"{{http://cwe.mitre.org/cwe-7}}{name}"


def _text(el: Optional[ET.Element]) -> str:
    """Safely get .text of an element (replaces XmlNode.InnerText)."""
    if el is None:
        return ""
    return "".join(el.itertext()).strip()


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------

def parse_cwe_xml(xml_path: str) -> None:
    """
    Replaces CWEParser.Program.Main():
      - Loads cwec_v4.0.xml
      - Iterates Weakness nodes
      - Inserts CWE + CWEWEAKNESS rows
    """
    log(MODULE, f"Loading CWE XML: {xml_path}")
    tree = ET.parse(xml_path)
    root = tree.getroot()

    weaknesses = root.findall(f".//{_tag('Weakness')}")
    log(MODULE, f"Found {len(weaknesses)} weakness entries")

    inserted_cwe = 0
    inserted_weak = 0

    with session_scope("XORCISM") as session:
        # Avoid circular import at module level
        # CWEWEAKNESS does not exist in the schema — relationships are stored in
        # CWERELATIONSHIPCATEGORY (RelationshipNature / RelationshipTargetCWEID).
        from xorcism_python.models.xorcism import CWE, CWERELATIONSHIPCATEGORY

        rel_counter = 1  # surrogate PK for CWERELATIONSHIPCATEGORY

        for weakness in weaknesses:
            cwe_id      = weakness.get("ID")
            name        = weakness.get("Name", "")
            abstraction = weakness.get("Abstraction", "")
            status      = weakness.get("Status", "")

            description = _text(weakness.find(_tag("Description")))

            # Related weaknesses (parents / children)
            related = []
            rw_section = weakness.find(_tag("Related_Weaknesses"))
            if rw_section is not None:
                for rw in rw_section.findall(_tag("Related_Weakness")):
                    related.append({
                        "nature":   rw.get("Nature", ""),
                        "cwe_id":   rw.get("CWE_ID", ""),
                    })

            # Upsert CWE  (CWEID is TEXT, description column is CWEDescriptionSummary)
            existing = session.query(CWE).filter(CWE.CWEID == str(cwe_id)).first()
            if existing is None:
                cwe_row = CWE(
                    CWEID=str(cwe_id),
                    CWEName=name[:255] if name else None,
                    CWEDescriptionSummary=description[:4000] if description else None,
                    CWEAbstraction=abstraction[:50] if abstraction else None,
                    CWEStatus=status[:50] if status else None,
                )
                session.add(cwe_row)
                inserted_cwe += 1
            else:
                existing.CWEName              = name[:255] if name else None
                existing.CWEDescriptionSummary = description[:4000] if description else None

            # Insert relationship rows into CWERELATIONSHIPCATEGORY
            for rw in related:
                rel_row = CWERELATIONSHIPCATEGORY(
                    CWERelationshipCategoryID=rel_counter,
                    CWEID=str(cwe_id),
                    RelationshipNature=rw["nature"][:255] if rw["nature"] else "",
                    RelationshipTargetCWEID=str(rw["cwe_id"]),
                )
                session.add(rel_row)
                rel_counter += 1
                inserted_weak += 1

        session.commit()
        log(MODULE, f"Inserted {inserted_cwe} CWE rows, {inserted_weak} relationship links")

    log(MODULE, "Done.")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Import MITRE CWE XML into XORCISM.db"
    )
    parser.add_argument(
        "--xml",
        default="cwec_latest.xml",
        help=(
            "Path to the local CWE XML file (default: cwec_latest.xml). "
            "If the file does not exist it is downloaded automatically from "
            f"{CWE_ZIP_URL}"
        ),
    )
    args = parser.parse_args()

    xml_path = ensure_cwe_xml(args.xml)
    parse_cwe_xml(xml_path)


if __name__ == "__main__":
    main()
