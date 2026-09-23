# Contributing to Warden

Thanks for your interest in improving Warden! This project is designed to make
contributions easy — most of the value lives in **data (rules)**, not code.

## Getting started

```bash
git clone https://github.com/your-username/warden
cd warden
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## Adding a new policy (no code required)

Policies are YAML files under `warden/rules/builtin/`. To add a check:

1. Pick or create a file (grouped by ecosystem, e.g. `aws_terraform.yaml`).
2. Add a rule following the existing schema:

   ```yaml
   - id: AWS_MY_NEW_RULE
     title: Short human-readable title
     severity: HIGH            # INFO | LOW | MEDIUM | HIGH | CRITICAL
     resource_types: [aws_s3_bucket]
     conditions:
       - path: some.attribute
         operator: equals      # see engine.py for the full operator list
         value: bad-value
     message: What is wrong and why it matters.
     remediation: How to fix it.
     tags: [public-exposure]   # tags feed the correlation engine
   ```

3. Add a resource that trips it to `examples/` and a test asserting it fires.
4. Run `pytest` and `ruff check .`.

## Adding a new parser

Create a module under `warden/parsers/` exposing `matches(path)` and
`parse(path) -> list[Resource]`, then register it in `warden/parsers/__init__.py`.

## Adding an attack chain

Attack chains are declarative `ChainTemplate`s in `warden/correlation.py`. Add a
template describing the tag combination and impact narrative, plus a test.

## Code style

* `ruff` for linting and import ordering.
* Keep the engine decoupled from parsers and reporters.
* Every new behaviour ships with a test.

## Commit messages

Use clear, conventional messages (`feat:`, `fix:`, `docs:`, `test:`).
