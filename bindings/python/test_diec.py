"""Tests for the diec Python bindings.

Run with::

    cargo build -p diec-ffi --release
    python -m pytest bindings/python/test_diec.py -v

Or directly::

    python bindings/python/test_diec.py
"""

from __future__ import annotations

import os
import pathlib
import sys
import unittest

# Add this directory to path so we can import diec without installation.
sys.path.insert(0, os.path.dirname(__file__))

import diec  # noqa: E402

DB_PATH = str(pathlib.Path(__file__).resolve().parent.parent.parent / "upstream" / "Detect-It-Easy" / "db")


def seven_zip_header() -> bytes:
    """Minimal 7-Zip file header (64 bytes)."""
    data = bytearray([0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04])
    data.extend(b"\x00" * (64 - len(data)))
    return bytes(data)


class TestAbiVersion(unittest.TestCase):
    def test_version_is_v1(self):
        self.assertEqual(diec.abi_version(), 0x00010000)

    def test_compatible_with_v1_0(self):
        self.assertTrue(diec.abi_compatible(0x00010000))

    def test_not_compatible_with_v2(self):
        self.assertFalse(diec.abi_compatible(0x00020000))


class TestStatusName(unittest.TestCase):
    def test_ok_name(self):
        self.assertEqual(diec.status_name(0), "OK")

    def test_unknown_name(self):
        self.assertEqual(diec.status_name(99), "UNKNOWN")


class TestScanBytes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not pathlib.Path(DB_PATH).is_dir():
            raise unittest.SkipTest(f"database not found: {DB_PATH}")
        cls.db = diec.Database.from_path(DB_PATH)

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "db"):
            cls.db.close()

    def test_scan_7zip(self):
        result = diec.scan_bytes(self.db, seven_zip_header())
        try:
            self.assertIn("7-Zip", result.json)
            self.assertGreater(result.detection_count, 0)
        finally:
            result.close()

    def test_scan_with_flags(self):
        result = diec.scan_bytes(self.db, seven_zip_header(), diec.FLAG_VERBOSE)
        try:
            self.assertGreaterEqual(result.detection_count, 0)
        finally:
            result.close()

    def test_context_manager(self):
        with diec.scan_bytes(self.db, seven_zip_header()) as result:
            self.assertIn("7-Zip", result.json)


class TestErrorHandling(unittest.TestCase):
    def test_nonexistent_path_raises(self):
        with self.assertRaises(diec.DiecError):
            diec.Database.from_path("/nonexistent/path/that/does/not/exist")


class TestReusableScanner(unittest.TestCase):
    """Verify the reusable Scanner API works across multiple scans.

    Regression test: the Python binding previously had no Scanner class
    at all, forcing users to use the one-shot scan_bytes/scan_path
    functions and pay the per-scan runtime construction cost.
    """

    @classmethod
    def setUpClass(cls):
        if not pathlib.Path(DB_PATH).is_dir():
            raise unittest.SkipTest(f"database not found: {DB_PATH}")
        cls.db = diec.Database.from_path(DB_PATH)

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "db"):
            cls.db.close()

    def test_scan_bytes_reuses_runtime(self):
        """Multiple scan_bytes calls on the same scanner must succeed."""
        with self.db.new_scanner() as scanner:
            # First scan.
            result1 = scanner.scan_bytes(seven_zip_header())
            try:
                self.assertIn("7-Zip", result1.json)
                self.assertGreater(result1.detection_count, 0)
            finally:
                result1.close()

            # Second scan (same data, runtime reused).
            result2 = scanner.scan_bytes(seven_zip_header())
            try:
                self.assertIn("7-Zip", result2.json)
                self.assertGreater(result2.detection_count, 0)
            finally:
                result2.close()

            # Third scan (different data, should not crash).
            empty = b"\x00" * 64
            result3 = scanner.scan_bytes(empty)
            result3.close()

    def test_scan_path_reuses_runtime(self):
        """scan_path on a reusable scanner must work."""
        corpus_zip = pathlib.Path(__file__).resolve().parent.parent.parent / "corpus" / "payload.zip"
        if not corpus_zip.is_file():
            self.skipTest("corpus/payload.zip not found")
        with self.db.new_scanner() as scanner:
            result = scanner.scan_path(str(corpus_zip))
            try:
                self.assertIn("Zip", result.json)
            finally:
                result.close()

    def test_context_manager_closes_scanner(self):
        """Scanner context manager must close the handle on exit."""
        scanner = self.db.new_scanner()
        scanner.close()
        # Double close must not crash.
        scanner.close()


if __name__ == "__main__":
    unittest.main()
