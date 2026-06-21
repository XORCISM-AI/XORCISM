"""Grafana connector — import datasource health + alert rules as Asset Monitoring monitors, and firing
alerts as monitoring incidents (MONITORINGCHECK / MONITORINGINCIDENT via runner.import_monitoring).

Offline: a JSON export via the `file` param. Live: GRAFANA_URL + GRAFANA_TOKEN (Bearer service account).
Returns {"monitors": [...], "monitoring_incidents": [...], "source": "Grafana"}.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import grc_common as g  # noqa: E402  (reuse http_json / rows)


def _status(state):
    s = str(state or "").lower()
    if any(k in s for k in ("firing", "alerting", "down", "critical")):
        return "down"
    if any(k in s for k in ("nodata", "no_data", "pending", "warn")):
        return "warning"
    if any(k in s for k in ("ok", "normal", "inactive", "up", "healthy")):
        return "up"
    return "unknown"


def _from_grafana(data):
    monitors, incidents = [], []
    for ds in g.rows(data.get("datasources", [])) if isinstance(data, dict) else []:
        monitors.append({"name": f"Grafana DS: {ds.get('name')}", "type": "grafana",
                         "target": ds.get("url") or ds.get("name"), "status": "up",
                         "external_id": f"ds:{ds.get('uid') or ds.get('id')}", "source": "Grafana"})
    for r in g.rows(data.get("alert_rules", [])) if isinstance(data, dict) else []:
        monitors.append({"name": r.get("title") or r.get("name"), "type": "grafana",
                         "target": r.get("uid"), "status": _status(r.get("state")),
                         "external_id": f"rule:{r.get('uid')}", "source": "Grafana"})
    for a in g.rows(data.get("alerts", [])) if isinstance(data, dict) else []:
        labels = a.get("labels", {}) or {}
        incidents.append({"title": labels.get("alertname") or "Grafana alert", "status": "down",
                          "severity": labels.get("severity") or "high", "started_at": a.get("startsAt"),
                          "external_id": a.get("fingerprint") or labels.get("alertname"), "source": "Grafana"})
    return {"monitors": monitors, "monitoring_incidents": incidents, "source": "Grafana"}


def run(params, workdir):
    f = params.get("file")
    if f and os.path.exists(f):
        with open(f, encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict) and ("monitors" in data or "monitoring_incidents" in data):
            data.setdefault("source", "Grafana")
            return data
        return _from_grafana(data)

    token = os.getenv("GRAFANA_TOKEN") or os.getenv("GRAFANA_API_KEY")
    base = (params.get("base") or os.getenv("GRAFANA_URL") or "").rstrip("/")
    if not base or not token:
        raise RuntimeError("Grafana: provide a `file` param or set GRAFANA_URL + GRAFANA_TOKEN.")
    hdr = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    cap = int(params.get("max_items") or 2000)
    monitors, incidents = [], []
    try:
        for ds in g.rows(g.http_json(base + "/api/datasources", hdr)):
            monitors.append({"name": f"Grafana DS: {ds.get('name')}", "type": "grafana",
                             "target": ds.get("url") or ds.get("name"), "status": "up",
                             "external_id": f"ds:{ds.get('uid') or ds.get('id')}", "source": "Grafana"})
    except Exception:  # noqa: BLE001
        pass
    try:
        for r in g.rows(g.http_json(base + "/api/v1/provisioning/alert-rules", hdr)):
            monitors.append({"name": r.get("title"), "type": "grafana", "target": r.get("uid"),
                             "status": "unknown", "external_id": f"rule:{r.get('uid')}", "source": "Grafana"})
    except Exception:  # noqa: BLE001
        pass
    try:
        for a in g.rows(g.http_json(base + "/api/alertmanager/grafana/api/v2/alerts", hdr)):
            labels = a.get("labels", {}) or {}
            incidents.append({"title": labels.get("alertname") or "Grafana alert", "status": "down",
                              "severity": labels.get("severity") or "high", "started_at": a.get("startsAt"),
                              "external_id": a.get("fingerprint") or labels.get("alertname"), "source": "Grafana"})
    except Exception:  # noqa: BLE001
        pass
    return {"monitors": monitors[:cap], "monitoring_incidents": incidents, "source": "Grafana"}
