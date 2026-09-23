"""Tests for the command-line interface and console reporter."""

import json

from rich.console import Console

from tests.conftest import EXAMPLES_DIR
from warden.cli import main
from warden.report import render_console
from warden.scan import scan_path


def test_cli_json_output_to_file(tmp_path, capsys):
    out = tmp_path / "report.json"
    code = main(["scan", EXAMPLES_DIR, "--format", "json", "--output", str(out)])
    assert code == 0
    payload = json.loads(out.read_text())
    assert payload["tool"] == "warden"
    assert payload["summary"]["findings"] > 0


def test_cli_sarif_stdout(capsys):
    code = main(["scan", EXAMPLES_DIR, "--format", "sarif"])
    assert code == 0
    sarif = json.loads(capsys.readouterr().out)
    assert sarif["version"] == "2.1.0"


def test_cli_fail_on_high_returns_nonzero():
    # The examples contain CRITICAL/HIGH findings, so --fail-on high must fail.
    code = main(["scan", EXAMPLES_DIR, "--fail-on", "high"])
    assert code == 1


def test_cli_fail_on_not_triggered_when_below_threshold(tmp_path):
    clean = tmp_path / "clean.tf"
    clean.write_text(
        'resource "aws_s3_bucket" "ok" {\n'
        '  bucket = "acme-ok"\n'
        '  acl    = "private"\n'
        "  server_side_encryption_configuration {}\n"
        "}\n"
    )
    code = main(["scan", str(clean), "--fail-on", "critical"])
    assert code == 0


def test_cli_rules_subcommand(capsys):
    code = main(["rules"])
    assert code == 0
    assert "policies loaded" in capsys.readouterr().out


def test_console_reporter_runs_without_error():
    result = scan_path(EXAMPLES_DIR)
    console = Console(record=True, width=100)
    render_console(result, console)
    text = console.export_text()
    assert "scan summary" in text
    assert "attack chain" in text.lower()


def test_console_reporter_clean_scan(tmp_path):
    clean = tmp_path / "clean.tf"
    clean.write_text('resource "aws_iam_role" "r" {\n  name = "r"\n}\n')
    result = scan_path(str(clean))
    console = Console(record=True, width=100)
    render_console(result, console)
    assert "Clean scan" in console.export_text()
