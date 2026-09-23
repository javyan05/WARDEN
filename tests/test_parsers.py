"""Tests for the IaC parsers against the bundled example files."""

import os

from tests.conftest import EXAMPLES_DIR
from warden.parsers import discover, parse_file
from warden.parsers.dockerfile import parse as parse_dockerfile
from warden.parsers.terraform import parse as parse_terraform


def test_discover_finds_all_example_files():
    files = discover(EXAMPLES_DIR)
    basenames = {os.path.basename(f) for f in files}
    assert "main.tf" in basenames
    assert "Dockerfile" in basenames
    assert "deployment.yaml" in basenames


def test_terraform_parser_normalizes_values():
    resources = parse_terraform(os.path.join(EXAMPLES_DIR, "terraform", "main.tf"))
    by_addr = {r.address: r for r in resources}
    bucket = by_addr["aws_s3_bucket.customer_data"]
    # Quotes and metadata keys must be stripped by the normaliser.
    assert bucket.attributes["acl"] == "public-read"
    assert "__is_block__" not in bucket.attributes
    # Booleans stay native types.
    assert by_addr["aws_db_instance.primary"].attributes["publicly_accessible"] is True


def test_terraform_parser_reports_line_numbers():
    resources = parse_terraform(os.path.join(EXAMPLES_DIR, "terraform", "main.tf"))
    bucket = next(r for r in resources if r.name == "customer_data")
    assert bucket.line > 1


def test_dockerfile_parser_detects_root_and_latest():
    resources = parse_dockerfile(os.path.join(EXAMPLES_DIR, "docker", "Dockerfile"))
    assert len(resources) == 1
    attrs = resources[0].attributes
    assert attrs["runs_as_root"] is True
    assert attrs["uses_latest_tag"] is True
    assert attrs["adds_remote_url"] is True


def test_kubernetes_parser_hoists_security_context():
    resources = parse_file(os.path.join(EXAMPLES_DIR, "kubernetes", "deployment.yaml"))
    deploy = next(r for r in resources if r.resource_type == "Deployment")
    assert deploy.attributes["host_network"] is True
    assert deploy.attributes["privileged_containers"] == ["api"]


def test_parse_file_dispatches_by_type():
    tf = parse_file(os.path.join(EXAMPLES_DIR, "terraform", "main.tf"))
    assert all(r.kind.value == "terraform" for r in tf)
