"""Warden — shift-left security scanner for Infrastructure-as-Code and containers.

Warden parses Terraform, Dockerfiles and Kubernetes manifests, evaluates them
against a policy-as-code rule set, detects hardcoded secrets, and correlates
individual findings into likely attack chains with a real risk score.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
