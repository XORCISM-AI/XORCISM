"""
sigma_convert.py — Convert a Sigma rule (YAML on stdin) to SPL / KQL / EQL using
pySigma, with production field-mapping pipelines (Windows/ECS/Sentinel-ASIM) and
a graceful fallback to the bare backend per target.

Output: a single JSON object on stdout, e.g.
  {"engine":"pysigma","version":"0.11.x","spl":"...","kql":"...","eql":"...","errors":{...}}
On a fatal error: {"error":"..."}. The XORCISM server (routes/sigma.ts) calls this
when available and otherwise falls back to its built-in TypeScript converter.

Install on the host: pip install pysigma pysigma-backend-splunk
                                 pysigma-backend-elasticsearch pysigma-backend-kusto
"""
import json
import sys


def _collection(text):
    from sigma.collection import SigmaCollection
    return SigmaCollection.from_yaml(text)


def _convert(makers, rule):
    """Try each backend factory in order; return (query, error)."""
    last = None
    for make in makers:
        try:
            out = make().convert(rule)
            if out and out[0]:
                return out[0], None
        except Exception as e:  # noqa: BLE001 — backend/pipeline may be unavailable
            last = e
    return None, (str(last) if last else "no output")


def _splunk(rule):
    def piped():
        from sigma.backends.splunk import SplunkBackend
        from sigma.pipelines.splunk import splunk_windows_pipeline
        return SplunkBackend(processing_pipeline=splunk_windows_pipeline())

    def bare():
        from sigma.backends.splunk import SplunkBackend
        return SplunkBackend()

    return _convert([piped, bare], rule)


def _eql(rule):
    def piped():
        from sigma.backends.elasticsearch import EqlBackend
        from sigma.pipelines.elasticsearch.windows import ecs_windows
        return EqlBackend(processing_pipeline=ecs_windows())

    def bare():
        from sigma.backends.elasticsearch import EqlBackend
        return EqlBackend()

    return _convert([piped, bare], rule)


def _kql(rule):
    def piped():
        from sigma.backends.kusto import KustoBackend
        from sigma.pipelines.sentinelasim import sentinel_asim_pipeline
        return KustoBackend(processing_pipeline=sentinel_asim_pipeline())

    def bare():
        from sigma.backends.kusto import KustoBackend
        return KustoBackend()

    return _convert([piped, bare], rule)


def main():
    text = sys.stdin.read()
    try:
        import sigma  # noqa: F401
    except Exception as e:  # noqa: BLE001
        print(json.dumps({"error": "pysigma not installed: %s" % e}))
        return
    try:
        rule = _collection(text)
    except Exception as e:  # noqa: BLE001
        print(json.dumps({"error": "Sigma parse error: %s" % e}))
        return

    res = {"engine": "pysigma"}
    try:
        from importlib.metadata import version as _ver
        res["version"] = _ver("pysigma")
    except Exception:  # noqa: BLE001
        pass
    errors = {}
    for key, fn in (("spl", _splunk), ("kql", _kql), ("eql", _eql)):
        q, err = fn(rule)
        if q is not None:
            res[key] = q
        if err:
            errors[key] = err
    if errors:
        res["errors"] = errors
    if not any(k in res for k in ("spl", "kql", "eql")):
        res = {"error": "no backend produced output", "details": errors}
    print(json.dumps(res))


if __name__ == "__main__":
    main()
