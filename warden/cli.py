"""Command-line interface.

    warden scan ./infra
    warden scan ./infra --format sarif --output warden.sarif
    warden scan ./infra --min-severity high --fail-on high
    warden rules            # list the loaded policy catalogue

The ``--fail-on`` flag is what makes Warden a CI gate: it sets the process exit
code so a pull request can be blocked when a finding at or above a threshold is
introduced.
"""

from __future__ import annotations

import argparse
import sys

from rich.console import Console

from warden import __version__
from warden.models import Severity
from warden.report import render_console, to_json, to_sarif
from warden.rules import load_all_rules
from warden.scan import scan_path


def _severity_arg(value: str) -> Severity:
    try:
        return Severity.from_str(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="warden",
        description="Shift-left security scanner for IaC and containers.",
    )
    parser.add_argument("--version", action="version", version=f"warden {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a file or directory.")
    scan.add_argument("target", help="Path to a file or directory to scan.")
    scan.add_argument(
        "--format",
        choices=["console", "json", "sarif"],
        default="console",
        help="Output format (default: console).",
    )
    scan.add_argument("--output", "-o", help="Write output to a file instead of stdout.")
    scan.add_argument("--policy-dir", help="Directory of custom policy YAML files.")
    scan.add_argument(
        "--min-severity",
        type=_severity_arg,
        default=Severity.INFO,
        help="Only report findings at or above this severity.",
    )
    scan.add_argument(
        "--fail-on",
        type=_severity_arg,
        default=None,
        help="Exit non-zero if any finding is at or above this severity (for CI).",
    )
    scan.add_argument("--no-secrets", action="store_true", help="Disable secret scanning.")
    scan.add_argument(
        "--no-correlation", action="store_true", help="Disable attack-chain correlation."
    )

    rules = sub.add_parser("rules", help="List the loaded policy catalogue.")
    rules.add_argument("--policy-dir", help="Directory of custom policy YAML files.")

    return parser


def _run_scan(args: argparse.Namespace) -> int:
    result = scan_path(
        args.target,
        policy_dir=args.policy_dir,
        min_severity=args.min_severity,
        include_secrets=not args.no_secrets,
        correlate_chains=not args.no_correlation,
    )

    if args.format == "json":
        output = to_json(result)
    elif args.format == "sarif":
        output = to_sarif(result)
    else:
        output = None  # rendered directly to the console below

    if output is not None:
        if args.output:
            with open(args.output, "w", encoding="utf-8") as handle:
                handle.write(output)
            Console(stderr=True).print(f"[green]Wrote {args.format} report to {args.output}[/green]")
        else:
            print(output)
    else:
        console = Console(file=open(args.output, "w", encoding="utf-8")) if args.output else Console()
        render_console(result, console)

    if args.fail_on is not None and result.highest_severity() >= args.fail_on:
        return 1
    return 0


def _run_rules(args: argparse.Namespace) -> int:
    console = Console()
    rules = sorted(load_all_rules(args.policy_dir), key=lambda r: (-int(r.severity), r.id))
    console.print(f"[bold]{len(rules)} policies loaded[/bold]\n")
    for rule in rules:
        console.print(f"[bold]{rule.id}[/bold]  ([italic]{rule.severity.name}[/italic])")
        console.print(f"  {rule.title}")
        console.print(f"  applies to: {', '.join(rule.resource_types)}\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _run_scan(args)
    if args.command == "rules":
        return _run_rules(args)
    parser.print_help()
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
