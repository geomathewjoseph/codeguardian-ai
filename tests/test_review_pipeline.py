import unittest

from pydantic import ValidationError

from app.sandbox import PatchValidationError, apply_single_file_unified_patch, run_isolated_test
from app.schemas import Finding
from app.model_validation import ModelOutputValidationError, validate_model_report
from app.security_engine import analyze_diff, parse_unified_diff
from app.server import FIXTURE_PRESETS


class DiffParserTests(unittest.TestCase):
    def test_added_line_uses_new_file_coordinate(self):
        parsed = parse_unified_diff(
            """diff --git a/example.py b/example.py
--- a/example.py
+++ b/example.py
@@ -7,2 +10,3 @@ def f():
 old = 1
+new = 2
 return old
"""
        )
        additions = parsed[0].added_lines
        self.assertEqual(len(additions), 1)
        self.assertEqual(additions[0].new_line, 11)
        self.assertIsNone(additions[0].old_line)

    def test_deleted_vulnerable_code_is_not_reported(self):
        report = analyze_diff(
            """diff --git a/run.py b/run.py
--- a/run.py
+++ b/run.py
@@ -1 +1 @@
-subprocess.run(f\"ping {host}\", shell=True)
+subprocess.run([\"ping\", host], shell=False)
"""
        )
        self.assertEqual(report.findings, [])
        self.assertEqual(report.verdict, "APPROVE")

    def test_malformed_non_git_input_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "No Git file headers"):
            analyze_diff("@@ -1 +1 @@\n+unsafe()")


class ReviewEngineTests(unittest.TestCase):
    def test_sql_fixture_has_exact_evidence_and_no_false_secret(self):
        report = analyze_diff(FIXTURE_PRESETS["sql_injection"])
        self.assertEqual(len(report.findings), 1)
        finding = report.findings[0]
        self.assertEqual(finding.rule_id, "CWE-89")
        self.assertEqual(finding.file, "auth/login.py")
        self.assertEqual(finding.line_start, 12)
        self.assertIn("SELECT * FROM users", finding.evidence[0])
        self.assertIsNone(finding.suggested_fix)
        self.assertEqual(finding.patch_status, "SUGGESTION_ONLY")
        self.assertEqual(report.counts.critical, 1)
        self.assertEqual(report.counts.high, 0)

    def test_finding_rejects_parent_path_and_reversed_range(self):
        with self.assertRaises(ValidationError):
            Finding(
                id="SEC-1", rule_id="CWE-1", title="bad", file="../secret.py",
                line_start=1, line_end=1, description="x", remediation="y",
            )

    def test_model_output_location_must_be_in_changed_hunk(self):
        diff = """diff --git a/safe.py b/safe.py
--- a/safe.py
+++ b/safe.py
@@ -1 +1 @@
-x = 1
+x = 2
"""
        model_output = {
            "version": "2.0.0", "summary": "bad location", "risk_level": "LOW", "verdict": "COMMENT",
            "counts": {"critical": 0, "high": 0, "medium": 0, "low": 1},
            "findings": [{
                "id": "MODEL-1", "rule_id": "CWE-1", "title": "Out of range", "category": "SECURITY",
                "severity": "LOW", "confidence": "LOW", "file": "safe.py", "line_start": 99, "line_end": 99,
                "evidence": ["x = 2"], "description": "x", "remediation": "y",
            }],
            "unit_tests": [], "execution_time_ms": 1, "analyzed_files": ["safe.py"],
            "engine": "model", "analyzers": ["model"], "timestamp": "2026-01-01T00:00:00Z",
        }
        with self.assertRaises(ModelOutputValidationError):
            validate_model_report(model_output, diff)
        with self.assertRaises(ValidationError):
            Finding(
                id="SEC-1", rule_id="CWE-1", title="bad", file="safe.py",
                line_start=3, line_end=2, description="x", remediation="y",
            )


class PatchValidationTests(unittest.TestCase):
    def test_valid_unified_patch_applies_in_memory(self):
        patch = """--- a/sample.py
+++ b/sample.py
@@ -1,2 +1,2 @@
 one = 1
-two = 2
+two = 3
"""
        result = apply_single_file_unified_patch("one = 1\ntwo = 2\n", patch, "sample.py")
        self.assertEqual(result, "one = 1\ntwo = 3\n")

    def test_patch_for_another_file_is_rejected(self):
        patch = """--- a/other.py
+++ b/other.py
@@ -1 +1 @@
-x = 1
+x = 2
"""
        with self.assertRaises(PatchValidationError):
            apply_single_file_unified_patch("x = 1\n", patch, "sample.py")

    def test_generated_code_is_not_executed_without_host_sandbox(self):
        result = run_isolated_test("raise AssertionError('must not run')")
        self.assertFalse(result["success"])
        self.assertEqual(result["status"], "UNAVAILABLE")
        self.assertIn("No code was executed", result["stderr"])


if __name__ == "__main__":
    unittest.main()
