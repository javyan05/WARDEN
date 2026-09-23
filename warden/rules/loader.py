"""Load rules from YAML files into :class:`~warden.engine.Rule` objects.

Rules ship as data (``warden/rules/builtin/*.yaml``) and users can point Warden
at their own directory of custom policies with ``--policy-dir``. Loading is
strict enough to fail loudly on a malformed rule rather than silently skip a
security check.
"""

from __future__ import annotations

import os
from typing import Any

import yaml

from warden.engine import Condition, Rule
from warden.models import Severity

_BUILTIN_DIR = os.path.dirname(__file__) + "/builtin"


def _condition_from_dict(data: dict[str, Any]) -> Condition:
    if "path" not in data or "operator" not in data:
        raise ValueError(f"Condition missing 'path' or 'operator': {data!r}")
    kwargs = {"path": data["path"], "operator": data["operator"]}
    if "value" in data:
        kwargs["value"] = data["value"]
    return Condition(**kwargs)


def _rule_from_dict(data: dict[str, Any], source: str) -> Rule:
    required = ("id", "title", "severity", "resource_types", "conditions", "message")
    missing = [key for key in required if key not in data]
    if missing:
        raise ValueError(f"Rule in {source} missing keys {missing}: {data.get('id', '?')}")

    return Rule(
        id=data["id"],
        title=data["title"],
        severity=Severity.from_str(data["severity"]),
        resource_types=list(data["resource_types"]),
        conditions=[_condition_from_dict(c) for c in data["conditions"]],
        message=data["message"],
        remediation=data.get("remediation", ""),
        tags=set(data.get("tags", [])),
        match=data.get("match", "all"),
    )


def load_rules_from_file(path: str) -> list[Rule]:
    with open(path, encoding="utf-8") as handle:
        document = yaml.safe_load(handle) or {}
    raw_rules = document.get("rules", document if isinstance(document, list) else [])
    return [_rule_from_dict(raw, path) for raw in raw_rules]


def load_rules_from_dir(directory: str) -> list[Rule]:
    rules: list[Rule] = []
    if not os.path.isdir(directory):
        return rules
    for filename in sorted(os.listdir(directory)):
        if filename.endswith((".yaml", ".yml")):
            rules.extend(load_rules_from_file(os.path.join(directory, filename)))
    return rules


def load_builtin_rules() -> list[Rule]:
    return load_rules_from_dir(_BUILTIN_DIR)


def load_all_rules(extra_dir: str | None = None) -> list[Rule]:
    """Built-in rules plus, optionally, a user-supplied policy directory."""
    rules = load_builtin_rules()
    if extra_dir:
        rules.extend(load_rules_from_dir(extra_dir))
    # De-duplicate by id, letting later (user) rules override built-ins.
    by_id = {rule.id: rule for rule in rules}
    return list(by_id.values())
