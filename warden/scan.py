"""Top-level scan orchestration.

Wires the pieces together: discover files -> parse into resources -> evaluate
policies -> scan for secrets -> correlate into attack chains -> return a
:class:`~warden.models.ScanResult`. Kept import-light and side-effect-free so it
is trivial to call from tests, the CLI, or another program.
"""

from __future__ import annotations

from warden.correlation import correlate
from warden.engine import PolicyEngine
from warden.models import ScanResult, Severity
from warden.parsers import discover, parse_file
from warden.rules import load_all_rules
from warden.scanners import secrets


def scan_path(
    target: str,
    policy_dir: str | None = None,
    min_severity: Severity = Severity.INFO,
    include_secrets: bool = True,
    correlate_chains: bool = True,
) -> ScanResult:
    """Scan a file or directory and return the full result."""
    rules = load_all_rules(policy_dir)
    engine = PolicyEngine(rules)

    files = discover(target)
    result = ScanResult()

    for path in files:
        resources = parse_file(path)
        result.resources.extend(resources)
        result.findings.extend(engine.evaluate(resources))
        if include_secrets:
            result.findings.extend(secrets.scan_file(path))

    # Apply the severity threshold before correlation so chains reflect what's shown.
    if min_severity > Severity.INFO:
        result.findings = [f for f in result.findings if f.severity >= min_severity]

    # Stable, useful ordering: severity desc, then file, then line.
    result.findings.sort(
        key=lambda f: (-int(f.severity), f.resource.file_path, f.resource.line)
    )

    if correlate_chains:
        result.chains = correlate(result.findings)

    return result
