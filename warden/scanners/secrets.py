"""Regex-based hardcoded-secret detection.

This scanner runs over the raw text of every discovered file, so it catches
secrets wherever they hide — a Terraform variable default, a Kubernetes env
value, an ``ARG`` in a Dockerfile. Each match becomes a Finding attached to a
synthetic Resource pointing at the exact line.

The patterns favour precision over recall (fewer false positives), and a Shannon
entropy check guards the noisier generic patterns.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

from warden.models import Finding, Resource, ResourceKind, Severity


@dataclass(frozen=True)
class SecretPattern:
    id: str
    title: str
    regex: re.Pattern
    severity: Severity
    min_entropy: float = 0.0  # 0 disables the entropy gate


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {ch: value.count(ch) for ch in set(value)}
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


# Ordered from most specific to most generic.
PATTERNS: list[SecretPattern] = [
    SecretPattern(
        "SECRET_AWS_ACCESS_KEY",
        "AWS access key ID",
        re.compile(r"(?<![A-Z0-9])((?:AKIA|ASIA|AGPA|AIDA)[A-Z0-9]{16})(?![A-Z0-9])"),
        Severity.CRITICAL,
    ),
    SecretPattern(
        "SECRET_AWS_SECRET_KEY",
        "AWS secret access key",
        re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*[\"']?([A-Za-z0-9/+]{40})[\"']?"),
        Severity.CRITICAL,
    ),
    SecretPattern(
        "SECRET_PRIVATE_KEY",
        "Private key material",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
        Severity.CRITICAL,
    ),
    SecretPattern(
        "SECRET_GITHUB_TOKEN",
        "GitHub token",
        re.compile(r"(?<![A-Za-z0-9])((?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,})"),
        Severity.HIGH,
    ),
    SecretPattern(
        "SECRET_SLACK_TOKEN",
        "Slack token",
        re.compile(r"(xox[baprs]-[A-Za-z0-9-]{10,})"),
        Severity.HIGH,
    ),
    SecretPattern(
        "SECRET_JWT",
        "JSON Web Token",
        re.compile(r"(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,})"),
        Severity.MEDIUM,
    ),
    SecretPattern(
        "SECRET_GENERIC_PASSWORD",
        "Hardcoded password/secret assignment",
        re.compile(
            r"(?i)(?:password|passwd|secret|api[_-]?key|token)\s*[=:]\s*[\"']([^\"'\s]{8,})[\"']"
        ),
        Severity.HIGH,
        min_entropy=2.5,
    ),
]

# Values that look like secrets but obviously are not, to cut false positives.
_ALLOWLIST = re.compile(
    r"(?i)^(?:changeme|password|example|placeholder|your[_-].*|xx+|<.*>|\$\{.*\}|null|none|true|false)$"
)


def scan_text(path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()

    for lineno, line in enumerate(text.splitlines(), start=1):
        for pattern in PATTERNS:
            match = pattern.regex.search(line)
            if not match:
                continue
            captured = match.group(match.lastindex or 0)
            if _ALLOWLIST.match(captured):
                continue
            if pattern.min_entropy and _shannon_entropy(captured) < pattern.min_entropy:
                continue

            key = (pattern.id, lineno)
            if key in seen:
                continue
            seen.add(key)

            resource = Resource(
                kind=ResourceKind.TERRAFORM,  # placeholder; secrets are file-level
                resource_type="secret",
                name=pattern.id.lower(),
                file_path=path,
                line=lineno,
            )
            findings.append(
                Finding(
                    rule_id=pattern.id,
                    title=pattern.title,
                    severity=pattern.severity,
                    resource=resource,
                    message=f"Possible {pattern.title.lower()} committed to source at line {lineno}.",
                    remediation=(
                        "Remove the value from version control, rotate the credential "
                        "immediately, and load it from a secret manager or environment "
                        "variable instead."
                    ),
                    tags={"hardcoded-secret", "credential-exposure"},
                )
            )
    return findings


def scan_file(path: str) -> list[Finding]:
    try:
        with open(path, encoding="utf-8", errors="ignore") as handle:
            text = handle.read()
    except OSError:  # pragma: no cover
        return []
    return scan_text(path, text)
