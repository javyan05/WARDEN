"""Reporters render a :class:`~warden.models.ScanResult` in different formats.

* ``console`` — a colourised, human-friendly summary (via ``rich``).
* ``json``    — machine-readable, stable schema for pipelines and dashboards.
* ``sarif``   — SARIF 2.1.0 so GitHub code scanning renders findings inline in PRs.

SARIF support is what lets Warden light up the "Security" tab of a GitHub repo,
which is a big part of why this project reads as production-grade rather than a
class exercise.
"""

from __future__ import annotations

import json
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from warden import __version__
from warden.models import ScanResult, Severity

_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

# GitHub code scanning only understands these SARIF levels.
_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def render_console(result: ScanResult, console: Console | None = None) -> None:
    console = console or Console()

    counts = result.counts_by_severity()
    summary = Text()
    for severity in reversed(Severity):
        n = counts[severity.name]
        style = _SEVERITY_STYLE[severity]
        summary.append(f" {severity.name}: {n} ", style=style if n else "dim")
    console.print(Panel(summary, title=f"Warden {__version__} — scan summary", expand=False))

    if not result.findings:
        console.print("[bold green]No findings. Clean scan.[/bold green]")
    else:
        table = Table(show_lines=False, header_style="bold")
        table.add_column("Severity", no_wrap=True)
        table.add_column("Rule", no_wrap=True)
        table.add_column("Resource")
        table.add_column("Location", no_wrap=True)
        for finding in result.findings:
            table.add_row(
                Text(finding.severity.name, style=_SEVERITY_STYLE[finding.severity]),
                finding.rule_id,
                finding.title,
                finding.location,
            )
        console.print(table)

    if result.chains:
        console.print()
        console.print("[bold underline]Correlated attack chains[/bold underline]")
        for chain in result.chains:
            body = Text()
            body.append(chain.narrative + "\n\n", style="italic")
            body.append("Findings: ", style="bold")
            body.append(", ".join(f.rule_id for f in chain.findings))
            console.print(
                Panel(
                    body,
                    title=f"[bold red]⛓ {chain.title}[/bold red]  (risk score {chain.score:.0f})",
                    border_style="red",
                    expand=False,
                )
            )


def to_json(result: ScanResult) -> str:
    payload: dict[str, Any] = {
        "tool": "warden",
        "version": __version__,
        "summary": {
            "resources_scanned": len(result.resources),
            "findings": len(result.findings),
            "by_severity": result.counts_by_severity(),
            "attack_chains": len(result.chains),
        },
        "findings": [f.to_dict() for f in result.findings],
        "attack_chains": [c.to_dict() for c in result.chains],
    }
    return json.dumps(payload, indent=2)


def to_sarif(result: ScanResult) -> str:
    # Collect the rules that actually fired for the SARIF "rules" catalogue.
    rules_index: dict[str, int] = {}
    sarif_rules: list[dict[str, Any]] = []
    for finding in result.findings:
        if finding.rule_id not in rules_index:
            rules_index[finding.rule_id] = len(sarif_rules)
            sarif_rules.append(
                {
                    "id": finding.rule_id,
                    "name": finding.title,
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.remediation or finding.title},
                    "defaultConfiguration": {"level": _SARIF_LEVEL[finding.severity]},
                    "properties": {"tags": sorted(finding.tags)},
                }
            )

    results = []
    for finding in result.findings:
        results.append(
            {
                "ruleId": finding.rule_id,
                "ruleIndex": rules_index[finding.rule_id],
                "level": _SARIF_LEVEL[finding.severity],
                "message": {"text": f"{finding.message} {finding.remediation}".strip()},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.resource.file_path},
                            "region": {"startLine": max(finding.resource.line, 1)},
                        }
                    }
                ],
            }
        )

    sarif = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Warden",
                        "informationUri": "https://github.com/your-username/warden",
                        "version": __version__,
                        "rules": sarif_rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)
