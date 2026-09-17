import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from osint_suite import cli, runner
from osint_suite.runner import ToolResult, ToolUnavailable
from osint_suite.tools import recon_ng


class CliTests(unittest.TestCase):
    def test_unavailable_tools_fail_and_are_recorded(self):
        cases = [
            (["domain", "example.com", "--tools", "whois"], cli.whois_tool),
            (["username", "fixture"], cli.sherlock),
            (["email", "fixture@example.com"], cli.holehe),
            (["phone", "+14155552671"], cli.phone_lookup),
            (["spiderfoot", "example.com"], cli.spiderfoot),
            (["shodan", "host", "192.0.2.1"], cli.shodan_tool),
            (["recon", "fixture", "--resource-file", "missing.rc"], cli.recon_ng),
            (["all", "fixture", "--type", "username"], cli.sherlock),
        ]
        for argv, module in cases:
            with self.subTest(command=argv[0]), tempfile.TemporaryDirectory() as tmp:
                with patch.object(runner, "RESULTS_ROOT", Path(tmp)), patch.object(module, "run", side_effect=ToolUnavailable("missing fixture tool")), contextlib.redirect_stdout(io.StringIO()):
                    code = cli.main(argv)
                self.assertEqual(code, 1)
                report = json.loads(next(Path(tmp).rglob("report.json")).read_text())
                self.assertEqual(len(report["tools"]), 1)
                self.assertFalse(report["tools"][0]["ok"])
                self.assertIn("missing fixture tool", report["tools"][0]["summary"])

    def test_partial_pipeline_failure_is_not_success(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(runner, "RESULTS_ROOT", Path(tmp)), patch.object(cli.whois_tool, "run", side_effect=ToolUnavailable("missing")), patch.object(cli.dnsrecon_tool, "run", return_value=ToolResult("dnsrecon", [], 0, 0)), contextlib.redirect_stdout(io.StringIO()):
            code = cli.main(["domain", "example.com", "--tools", "whois", "dnsrecon"])
            report = json.loads(next(Path(tmp).rglob("report.json")).read_text())
        self.assertEqual(code, 1)
        self.assertEqual([tool["ok"] for tool in report["tools"]], [False, True])

    def test_invalid_pivot_options_are_rejected_before_creating_run(self):
        for option in (["--depth", "-1"], ["--max-events", "0"], ["--modules", "typo"]):
            with self.subTest(option=option), patch.object(cli, "new_run_dir") as create, patch.object(cli.pivot, "run_pivot", return_value=([], [])), contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    cli.main(["pivot", "example.com", "--type", "domain", *option])
                self.assertEqual(error.exception.code, 2)
                create.assert_not_called()

    def test_recon_resource_file_is_absolute_for_tool_working_directory(self):
        # The wrapper changes cwd to the results directory before executing.
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as tmp:
            root = Path(tmp)
            resource = root / "commands.rc"
            resource.write_text("exit\n")
            with patch.object(recon_ng, "require_binary", return_value="recon-ng"), patch.object(recon_ng, "run_cmd", return_value=ToolResult("recon-ng", [], 0, 0)) as run:
                recon_ng.run("fixture", str(resource.relative_to(Path.cwd())), root / "results")
            cmd = run.call_args.args[1]
            self.assertEqual(cmd[cmd.index("-r") + 1], str(resource))


if __name__ == "__main__":
    unittest.main()
