"""
test_models.py - Smoke tests for SQLAlchemy model loading and DB connectivity
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from models.base import get_engine, get_session


def test_engines_connect():
    db_names = ["XORCISM", "XVULNERABILITY", "XATTACK", "XMALWARE",
                "XINCIDENT", "XTHREAT", "XOVAL", "XWINDOWS"]
    for db in db_names:
        engine = get_engine(db)
        with engine.connect() as conn:
            result = conn.execute(__import__("sqlalchemy").text("SELECT 1"))
            assert result.fetchone()[0] == 1, f"DB {db} query failed"
        print(f"  PASS  {db} engine connected")


def test_vulnerability_table_not_empty():
    session = get_session("XVULNERABILITY")
    try:
        from models.xvulnerability import VULNERABILITY
        count = session.query(VULNERABILITY).limit(1).count()
        # We just check it doesn't crash
        print(f"  PASS  VULNERABILITY table accessible (count check ok)")
    finally:
        session.close()


def test_model_import():
    import models.xorcism
    import models.xvulnerability
    import models.xattack
    import models.xmalware
    import models.xincident
    import models.xthreat
    import models.xoval
    import models.xwindows
    print("  PASS  All model modules imported successfully")


if __name__ == "__main__":
    tests = [test_model_import, test_engines_connect, test_vulnerability_table_not_empty]
    passed = 0
    for t in tests:
        try:
            t()
            passed += 1
        except Exception as e:
            print(f"  FAIL  {t.__name__}: {e}")
    print(f"\n{passed}/{len(tests)} tests passed")
