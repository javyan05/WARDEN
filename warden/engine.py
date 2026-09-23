"""The policy engine: a small, readable policy-as-code evaluator.

Rules are plain YAML — no plugin code required to add a check. Each rule targets
a resource type and lists ``conditions``; when every condition matches, the rule
raises a Finding. Conditions are deliberately minimal but composable:

    - path: server_side_encryption_configuration
      operator: absent

    - path: acl
      operator: equals
      value: public-read

Supported operators: equals, not_equals, in, not_in, present, absent,
contains, not_contains, regex, gt, lt, truthy, falsy. Paths are dotted and may
descend into lists (``containers.securityContext.privileged`` checks every
container). This keeps the DSL declarative while covering the real checks.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from warden.models import Finding, Resource, Severity

_MISSING = object()


def get_path(obj: Any, path: str) -> list[Any]:
    """Resolve a dotted ``path`` against ``obj``, fanning out over lists.

    Returns a list of every value the path resolves to. An empty list means the
    path is absent. Descending into a list applies the remaining path to each
    element, which is what makes ``containers.securityContext.privileged`` mean
    "for any container".
    """
    if path == "":
        return [obj]

    head, _, tail = path.partition(".")
    results: list[Any] = []

    if isinstance(obj, list):
        for item in obj:
            results.extend(get_path(item, path))
        return results

    if isinstance(obj, dict) and head in obj:
        value = obj[head]
        if tail:
            results.extend(get_path(value, tail))
        else:
            results.append(value)
    return results


@dataclass
class Condition:
    path: str
    operator: str
    value: Any = _MISSING

    def evaluate(self, resource: Resource) -> bool:
        found = get_path(resource.attributes, self.path)
        op = self.operator

        if op == "present":
            return len(found) > 0
        if op == "absent":
            return len(found) == 0
        if op == "truthy":
            return any(bool(v) for v in found)
        if op == "falsy":
            return len(found) == 0 or all(not bool(v) for v in found)

        # Remaining operators compare against self.value across all matches.
        if op == "equals":
            return any(v == self.value for v in found)
        if op == "not_equals":
            return len(found) > 0 and all(v != self.value for v in found)
        if op == "in":
            return any(v in self.value for v in found)
        if op == "not_in":
            return len(found) > 0 and all(v not in self.value for v in found)
        if op == "contains":
            return any(self.value in v for v in found if isinstance(v, (str, list, dict)))
        if op == "not_contains":
            return all(
                self.value not in v for v in found if isinstance(v, (str, list, dict))
            )
        if op == "regex":
            pattern = re.compile(self.value)
            return any(isinstance(v, str) and pattern.search(v) for v in found)
        if op == "gt":
            return any(isinstance(v, (int, float)) and v > self.value for v in found)
        if op == "lt":
            return any(isinstance(v, (int, float)) and v < self.value for v in found)

        raise ValueError(f"Unknown operator: {op!r}")


@dataclass
class Rule:
    id: str
    title: str
    severity: Severity
    resource_types: list[str]
    conditions: list[Condition]
    message: str
    remediation: str = ""
    tags: set[str] = None  # type: ignore[assignment]
    match: str = "all"  # "all" or "any"

    def __post_init__(self) -> None:
        if self.tags is None:
            self.tags = set()

    def applies_to(self, resource: Resource) -> bool:
        return "*" in self.resource_types or resource.resource_type in self.resource_types

    def evaluate(self, resource: Resource) -> Finding | None:
        if not self.applies_to(resource):
            return None
        checks = (cond.evaluate(resource) for cond in self.conditions)
        matched = all(checks) if self.match == "all" else any(checks)
        if not matched:
            return None
        return Finding(
            rule_id=self.id,
            title=self.title,
            severity=self.severity,
            resource=resource,
            message=self.message,
            remediation=self.remediation,
            tags=set(self.tags),
        )


class PolicyEngine:
    """Holds a set of rules and evaluates resources against all of them."""

    def __init__(self, rules: Iterable[Rule]):
        self.rules = list(rules)

    def evaluate(self, resources: Iterable[Resource]) -> list[Finding]:
        findings: list[Finding] = []
        for resource in resources:
            for rule in self.rules:
                finding = rule.evaluate(resource)
                if finding is not None:
                    findings.append(finding)
        return findings
