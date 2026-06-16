"""
test_utils.py - Unit tests for utils.py
Replaces XCommon.Tests (if they existed in the original)
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from utils import hash_string, hash_hex, Algorithm, RIGHT, check_right, log


def test_hash_md5_returns_string():
    result = hash_string("hello", Algorithm.MD5)
    assert isinstance(result, str)
    assert len(result) > 0


def test_hash_sha1_returns_string():
    result = hash_string("hello", Algorithm.SHA1)
    assert isinstance(result, str)


def test_hash_hex_md5():
    result = hash_hex("hello")
    assert result == "5d41402abc4b2a76b9719d911017c592"


def test_hash_hex_sha1():
    result = hash_hex("hello", Algorithm.SHA1)
    assert result == "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"


def test_check_right_no_session():
    # Without a session, should return True (permissive fallback)
    result = check_right(user_id=1, securable_type="CVE", right=RIGHT.VIEW)
    assert result is True


def test_log_does_not_raise():
    log("TestModule", "Test message — no exception expected")


if __name__ == "__main__":
    # Run without pytest
    tests = [
        test_hash_md5_returns_string,
        test_hash_sha1_returns_string,
        test_hash_hex_md5,
        test_hash_hex_sha1,
        test_check_right_no_session,
        test_log_does_not_raise,
    ]
    passed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
            passed += 1
        except Exception as e:
            print(f"  FAIL  {t.__name__}: {e}")
    print(f"\n{passed}/{len(tests)} tests passed")
