"""gen_readmes.py — generate a README.md for every XORCISM connector from its manifest.

Walks connectors/<id>/connector.json and writes a consistent connectors/<id>/README.md
derived from the manifest (name, type, category, description, parameters, command/run,
parser, permission). Connectors are auto-discovered by the server from these manifests,
so the README is documentation only.

    python connectors/gen_readmes.py            # create missing READMEs (skip existing)
    python connectors/gen_readmes.py --force    # regenerate all
    python connectors/gen_readmes.py --check     # report only, write nothing

The manifest is the source of truth — edit connector.json, then regenerate.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
_URL = re.compile(r"https?://[^\s)>\]\"']+")
_ENVVAR = re.compile(r"\b[A-Z][A-Z0-9]+(?:_[A-Z0-9]+)+\b")  # FOO_BAR style env vars


def _esc(s: Any) -> str:
    """Escape a cell for a Markdown table (pipes + newlines)."""
    return re.sub(r"\s+", " ", str(s or "")).replace("|", "\\|").strip()


def _upstream(desc: str) -> Optional[str]:
    urls = _URL.findall(desc or "")
    if not urls:
        return None
    for u in urls:  # prefer a source repo
        if "github.com" in u or "gitlab.com" in u:
            return u.rstrip(".,;)")
    return urls[0].rstrip(".,;)")


def _sample_file(cdir: str) -> Optional[str]:
    for f in sorted(os.listdir(cdir)):
        if f.lower().startswith("sample.") and not f.endswith(".py"):
            return f
    return None


def _params_table(params: List[Dict[str, Any]]) -> str:
    if not params:
        return "_No parameters._"
    rows = ["| Name | Type | Required | Default | Description |",
            "|------|------|----------|---------|-------------|"]
    for p in params:
        name = f"`{p.get('name', '')}`"
        typ = p.get("type", "")
        if typ == "enum" and p.get("values"):
            typ = "enum"
        req = "yes" if p.get("required") else "no"
        dflt = p.get("default", None)
        dflt = f"`{dflt}`" if dflt not in (None, "") else "—"
        help_txt = p.get("help", "")
        extra = []
        if p.get("values"):
            extra.append("one of: " + ", ".join(f"`{v}`" for v in p["values"]))
        if p.get("min") is not None or p.get("max") is not None:
            extra.append(f"range {p.get('min', '')}–{p.get('max', '')}")
        if extra:
            help_txt = (help_txt + " (" + "; ".join(extra) + ")") if help_txt else "; ".join(extra)
        rows.append(f"| {name} | {typ} | {req} | {dflt} | {_esc(help_txt)} |")
    return "\n".join(rows)


def _how_it_works(m: Dict[str, Any]) -> str:
    t = m.get("type", "")
    if t == "import":
        run = m.get("run", "run.py")
        return (
            f"This is an **import** connector. `{run}` exposes `run(params, workdir)` and returns the "
            "normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` "
            "or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and "
            "findings become **vulnerabilities**. The connector performs **no database access** itself, "
            "so it is safe to run on a remote worker."
        )
    if t == "tool-runner":
        cmd = " ".join(m.get("command", [])) or f"`{m.get('binary', '')}` …"
        out = m.get("output", {}) or {}
        parser = m.get("parser", "")
        okind = out.get("kind", "file")
        oext = out.get("ext", "")
        return (
            f"This is a **tool-runner** connector. It executes the `{m.get('binary', '')}` tool "
            "(resolved on the worker `PATH`) and parses its output. The command is run as an argv array "
            "(no shell); `{{param}}`, `{{outfile}}` and `{{workdir}}` are substituted with validated values:\n\n"
            f"```\n{cmd}\n```\n\n"
            f"Output: **{okind}**" + (f" (`.{oext}`)" if oext else "") +
            (f", parsed by `{parser}`" if parser else "") +
            " into the normalized `{assets, services, cpes, vulns}` result."
        )
    if t == "enrichment":
        return "This is an **enrichment** connector: it augments existing records rather than importing new ones."
    if t == "export":
        return "This is an **export** connector: it emits XORCISM data to an external format/destination."
    return f"Connector type: **{t}**."


def render(m: Dict[str, Any], cdir: str) -> str:
    name = m.get("name") or m.get("id", "Connector")
    cid = m.get("id", "")
    typ = m.get("type", "")
    cat = m.get("category", "")
    desc = m.get("description", "")
    intrusive = bool(m.get("intrusive"))
    perm = m.get("permission", f"connector:{cid}")
    sample = _sample_file(cdir)
    upstream = _upstream(desc)

    badges = [f"`{cid}`", f"**{typ}** connector"]
    if cat:
        badges.append(f"category **{cat}**")
    if intrusive:
        badges.append("⚠️ **intrusive** (engagement scope enforced)")
    head = " · ".join(badges)

    parts: List[str] = [f"# {name}", "", head, ""]
    if desc:
        parts += [desc, ""]
    if upstream:
        parts += [f"**Upstream:** {upstream}", ""]

    parts += ["## Parameters", "", _params_table(m.get("parameters", [])), ""]
    parts += ["## How it works", "", _how_it_works(m), ""]

    run_lines = [
        "## Running it",
        "",
        f"- **From XORCISM** — open **Connectors**, choose *{name}*, fill in the parameters and run it "
        f"(admin only; this creates a job consumed by the Python worker `connectors/runner.py`). "
        f"Required permission: `{perm}`.",
    ]
    if sample:
        run_lines.append(
            f"- **Self-test** — parse **and import** the bundled `{sample}` (no live tool):\n\n"
            f"  ```bash\n  python connectors/runner.py --selftest connectors/{cid}/{sample} --connector {cid}\n  ```\n"
            f"  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data."
        )
    parts += run_lines + [""]

    if _ENVVAR.search(desc) or re.search(r"\b(api[ _-]?key|secret|token|credential|environment)\b", desc, re.I):
        parts += [
            "## Secrets & configuration",
            "",
            "API keys and other secrets are read from the **worker environment** — never entered in the "
            "XORCISM UI. See the description above for the exact variable names.",
            "",
        ]

    parts += [
        "---",
        f"<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. "
        f"Edit the manifest (not this file), then regenerate.</sub>",
        "",
    ]
    return "\n".join(parts)


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate README.md for each XORCISM connector")
    ap.add_argument("--force", action="store_true", help="overwrite existing README.md")
    ap.add_argument("--check", action="store_true", help="report only; write nothing")
    args = ap.parse_args()

    created = skipped = errors = 0
    for d in sorted(os.listdir(HERE)):
        cdir = os.path.join(HERE, d)
        man = os.path.join(cdir, "connector.json")
        if not os.path.isdir(cdir) or not os.path.isfile(man):
            continue
        try:
            m = json.load(open(man, encoding="utf-8"))
        except Exception as e:  # noqa: BLE001
            print(f"[ERR] {d}: bad connector.json ({e})")
            errors += 1
            continue
        readme = os.path.join(cdir, "README.md")
        if os.path.exists(readme) and not args.force:
            skipped += 1
            continue
        if args.check:
            print(f"[would write] {d}/README.md")
            created += 1
            continue
        with open(readme, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(render(m, cdir))
        created += 1

    verb = "would create" if args.check else "wrote"
    print(f"\n{verb} {created} README.md, skipped {skipped} existing, {errors} manifest error(s).")


if __name__ == "__main__":
    main()
