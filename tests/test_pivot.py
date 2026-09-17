import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from osint_suite import pivot
from osint_suite.runner import ToolResult, ToolUnavailable


class PivotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def result(self, data, suffix=".json"):
        path = self.root / ("fixture" + suffix)
        path.write_text(json.dumps(data) if suffix == ".json" else data)
        return ToolResult("fixture", [], 0, 0, output_files=[path])

    def test_external_domains_reach_central_scope_filter(self):
        fixtures = [
            (pivot._extract_theharvester, {"hosts": ["external.test:192.0.2.1"]}, ".json"),
            (pivot._extract_amass, "external.test\n", ".txt"),
            (pivot._extract_dnsrecon, [{"name": "external.test"}], ".json"),
            (pivot._extract_spiderfoot, [{"type": "Internet Name", "data": "external.test"}], ".json"),
        ]
        for extract, data, suffix in fixtures:
            with self.subTest(extractor=extract.__name__):
                self.assertIn((pivot.SUBDOMAIN, "external.test"), extract(self.result(data, suffix), "example.com"))

    def test_scope_and_provenance(self):
        for allow_external in (False, True):
            called = []

            def run(value, directory):
                called.append(value)
                return ToolResult("fixture", [], 0, 0)

            discoveries = [(pivot.SUBDOMAIN, "sub.example.com"), (pivot.SUBDOMAIN, "external.test"), (pivot.SUBDOMAIN, "fakeexample.com")]
            module = pivot.PivotModule("fixture", {pivot.DOMAIN, pivot.SUBDOMAIN}, run, lambda *_: discoveries)
            with self.subTest(allow_external=allow_external), patch.object(pivot, "_modules", return_value=[module]), contextlib.redirect_stdout(io.StringIO()):
                _, graph = pivot.run_pivot("example.com", pivot.DOMAIN, self.root, allow_external=allow_external)
                self.assertEqual(called, ["example.com", "sub.example.com"] + (["external.test", "fakeexample.com"] if allow_external else []))
                self.assertEqual(graph[1]["parent"], "domain:example.com")
                self.assertEqual(graph[1]["source_module"], "fixture")

    def test_missing_module_is_in_results_and_graph(self):
        def unavailable(*_):
            raise ToolUnavailable("missing fixture tool")

        module = pivot.PivotModule("fixture", {pivot.DOMAIN}, unavailable, lambda *_: [])
        with patch.object(pivot, "_modules", return_value=[module]), contextlib.redirect_stdout(io.StringIO()):
            results, graph = pivot.run_pivot("example.com", pivot.DOMAIN, self.root)
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0].ok)
        self.assertEqual(len(graph), 1)
        self.assertFalse(graph[0]["ok"])

    def test_event_cap_with_empty_queue_does_not_report_truncation(self):
        module = pivot.PivotModule("fixture", {pivot.DOMAIN, pivot.SUBDOMAIN}, lambda *_: ToolResult("fixture", [], 0, 0), lambda *_: [(pivot.SUBDOMAIN, "sub.example.com")])
        output = io.StringIO()
        with patch.object(pivot, "_modules", return_value=[module]), contextlib.redirect_stdout(output):
            results, _ = pivot.run_pivot("example.com", pivot.DOMAIN, self.root, max_events=2)
        self.assertEqual(len(results), 2)
        self.assertNotIn("hit --max-events", output.getvalue())

    def test_event_cap_stops_followups_and_reports_remaining(self):
        module = pivot.PivotModule(
            "fixture", {pivot.DOMAIN, pivot.SUBDOMAIN},
            lambda *_: ToolResult("fixture", [], 0, 0),
            lambda *_: [(pivot.SUBDOMAIN, "one.example.com"), (pivot.SUBDOMAIN, "two.example.com")],
        )
        output = io.StringIO()
        with patch.object(pivot, "_modules", return_value=[module]), contextlib.redirect_stdout(output):
            results, _ = pivot.run_pivot("example.com", pivot.DOMAIN, self.root, max_events=2)
        self.assertEqual(len(results), 2)
        self.assertIn("1 discovered entit(y/ies) left unprocessed", output.getvalue())

    def test_failed_results_do_not_trigger_followups(self):
        module = pivot.PivotModule(
            "fixture", {pivot.DOMAIN, pivot.SUBDOMAIN},
            lambda *_: ToolResult("fixture", [], 1, 0),
            lambda *_: [(pivot.SUBDOMAIN, "sub.example.com")],
        )
        with patch.object(pivot, "_modules", return_value=[module]), contextlib.redirect_stdout(io.StringIO()):
            results, _ = pivot.run_pivot("example.com", pivot.DOMAIN, self.root)
        self.assertEqual(len(results), 1)

    def test_invalid_api_options_do_not_start_tools(self):
        for options in ({"max_depth": -1}, {"max_events": 0}, {"module_names": ["typo"]}):
            with self.subTest(options=options), patch.object(pivot.dnsrecon_tool, "run") as run:
                with self.assertRaises(ValueError):
                    pivot.run_pivot("example.com", pivot.DOMAIN, self.root, **options)
                run.assert_not_called()

    def test_graph_files_include_provenance(self):
        graph = [{
            "depth": 1, "module": "dnsrecon", "input_type": "subdomain",
            "input_value": "sub.example.com", "ok": True,
            "source_module": "theharvester", "parent": "domain:example.com",
        }]
        md_path = pivot.write_graph(self.root, graph, "example.com", pivot.DOMAIN)
        self.assertIn("Discovered by theharvester from `domain:example.com`", md_path.read_text())
        self.assertEqual(json.loads((self.root / "pivot-graph.json").read_text()), graph)


if __name__ == "__main__":
    unittest.main()
