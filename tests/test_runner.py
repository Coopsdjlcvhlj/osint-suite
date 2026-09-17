import json
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from osint_suite import runner
from osint_suite.report import write_report


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_runs_at_same_time_do_not_overwrite_results(self):
        with patch.object(runner, "RESULTS_ROOT", self.root), patch.object(runner, "datetime") as clock:
            clock.now.return_value = datetime(2026, 9, 17, tzinfo=timezone.utc)
            first = runner.new_run_dir("example.com")
            (first / "report.json").write_text("original")
            second = runner.new_run_dir("example.com")
        self.assertNotEqual(first, second)
        self.assertEqual((first / "report.json").read_text(), "original")
        self.assertTrue(second.is_dir())

    def test_dot_targets_stay_under_results_root(self):
        with patch.object(runner, "RESULTS_ROOT", self.root):
            for target in (".", "..", "../..", "", "../example.com"):
                with self.subTest(target=target):
                    run_dir = runner.new_run_dir(target)
                    self.assertEqual(run_dir.resolve().parent.parent, self.root)

    def test_concurrent_runs_get_separate_directories(self):
        with patch.object(runner, "RESULTS_ROOT", self.root), patch.object(runner, "datetime") as clock:
            clock.now.return_value = datetime(2026, 9, 17, tzinfo=timezone.utc)
            with ThreadPoolExecutor(max_workers=4) as pool:
                paths = list(pool.map(runner.new_run_dir, ["example.com"] * 12))
        self.assertEqual(len(set(paths)), 12)
        self.assertTrue(all(path.is_dir() for path in paths))

    def test_timeout_preserves_partial_output_and_writes_report(self):
        script = "import time; print('partial output', flush=True); time.sleep(60)"
        result = runner.run_cmd("fixture", [sys.executable, "-c", script], self.root, timeout=0.3)
        self.assertFalse(result.ok)
        self.assertIn("partial output", result.stdout_path.read_text())
        self.assertIn("timed out", result.stderr_path.read_text())
        json_path, _ = write_report("fixture", self.root, [result])
        self.assertFalse(json.loads(json_path.read_text())["tools"][0]["ok"])

    def test_missing_executable_is_reportable(self):
        result = runner.run_cmd("fixture", [str(self.root / "missing")], self.root)
        self.assertEqual(result.returncode, 127)
        self.assertTrue(result.stderr_path.read_text())

    def test_unexecutable_file_is_reportable(self):
        binary = self.root / "not-executable"
        binary.write_text("fixture")
        result = runner.run_cmd("fixture", [str(binary)], self.root)
        self.assertEqual(result.returncode, 126)
        self.assertTrue(result.stderr_path.read_text())

    def test_non_utf8_output_does_not_crash(self):
        result = runner.run_cmd("fixture", [sys.executable, "-c", "import os; os.write(1, b'\\xff')"], self.root)
        self.assertTrue(result.ok)
        self.assertEqual(result.stdout_path.read_text(), "\ufffd")

    def test_nonzero_exit_keeps_both_logs(self):
        script = "import sys; print('output'); print('error', file=sys.stderr); sys.exit(3)"
        result = runner.run_cmd("fixture", [sys.executable, "-c", script], self.root)
        self.assertEqual(result.returncode, 3)
        self.assertEqual(result.stdout_path.read_text(), "output\n")
        self.assertEqual(result.stderr_path.read_text(), "error\n")


if __name__ == "__main__":
    unittest.main()
