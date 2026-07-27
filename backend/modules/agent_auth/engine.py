# AEGIS Module 2: Agent Authorization Engine
# Deterministic IAM-style policy enforcement for AI agents

import re
import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class AuthorizationResult:
    authorized: bool
    policy_id: Optional[str] = None
    policy_name: Optional[str] = None
    conditions_met: bool = True
    matched_action: Optional[str] = None
    denied_reason: Optional[str] = None
    audit_id: Optional[str] = None
    latency_ms: float = 0.0


class PolicyEngine:
    """
    Deterministic policy engine for AI agent tool-call authorization.
    Inspired by AWS IAM - policies define what actions an agent can take
    on which resources under what conditions.
    """

    def __init__(self, db_session=None, cache_client=None):
        self.db = db_session
        self.cache = cache_client

    def _resolve_variable(self, value: str, context: dict) -> str:
        """Resolve {variable} interpolations in policy values."""
        def replace_var(match):
            var_name = match.group(1)
            # Walk dotted path in context
            parts = var_name.split(".")
            current = context
            for part in parts:
                if isinstance(current, dict):
                    current = current.get(part, "")
                else:
                    return ""
            return str(current) if current is not None else ""

        return re.sub(r"\{(\w+(?:\.\w+)*)\}", replace_var, value)

    def _match_resource(self, resource_pattern: str, actual_resource: str) -> bool:
        """Match a resource pattern against an actual resource path.

        Supports:
        - Exact match: filesystem:/reports/public/q1.pdf
        - Wildcard: filesystem:/reports/public/*
        - Category: filesystem:/reports/*
        - Global: *
        """
        if resource_pattern == "*":
            return True

        # Convert glob pattern to regex
        regex_pattern = re.escape(resource_pattern).replace(r"\*", ".*")
        return bool(re.match(f"^{regex_pattern}$", actual_resource))

    def _evaluate_condition(self, condition: dict, context: dict) -> bool:
        """Evaluate a single policy condition."""
        key = condition.get("key", "")
        op = condition.get("operator", "eq")
        expected = condition.get("value", "")

        # Resolve variables in the expected value
        expected = self._resolve_variable(str(expected), context)

        # Get the actual value from context
        actual = context
        for part in key.split("."):
            if isinstance(actual, dict):
                actual = actual.get(part, None)
            else:
                actual = None
                break

        if actual is None:
            return False

        actual_str = str(actual)

        if op == "eq":
            return actual_str == expected
        elif op == "neq":
            return actual_str != expected
        elif op == "in":
            return actual_str in expected.split(",")
        elif op == "gt":
            try:
                return float(actual_str) > float(expected)
            except (ValueError, TypeError):
                return False
        elif op == "gte":
            try:
                return float(actual_str) >= float(expected)
            except (ValueError, TypeError):
                return False
        elif op == "lt":
            try:
                return float(actual_str) < float(expected)
            except (ValueError, TypeError):
                return False
        elif op == "lte":
            try:
                return float(actual_str) <= float(expected)
            except (ValueError, TypeError):
                return False
        elif op == "contains":
            return expected in actual_str
        elif op == "regex":
            return bool(re.match(expected, actual_str))

        return False

    def authorize_tool_call(
        self,
        agent_id: str,
        tool_name: str,
        tool_params: dict,
        policies: list[dict],
        context: dict,
    ) -> AuthorizationResult:
        """
        Authorize a single tool call against a set of policies.

        Args:
            agent_id: The agent making the call
            tool_name: The tool being called (e.g. "read_file", "query_database")
            tool_params: Parameters of the tool call
            policies: List of policy documents to evaluate
            context: Session context (user_id, role, session_metadata)

        Returns:
            AuthorizationResult with decision and metadata
        """
        import time
        start = time.time()

        # Construct the resource identifier from the tool call
        if "path" in tool_params:
            resource = f"{tool_name}:{tool_params['path']}"
        elif "table" in tool_params:
            resource = f"database:{tool_params['table']}"
        elif "url" in tool_params:
            resource = f"web:{tool_params['url']}"
        elif "email" in tool_params:
            resource = f"email:{tool_params.get('to', '*')}"
        elif "channel" in tool_params:
            resource = f"slack:{tool_params['channel']}"
        else:
            # Fall back to tool name as resource
            resource = tool_name

        # Sort policies by priority (lower number = higher priority)
        sorted_policies = sorted(policies, key=lambda p: p.get("priority", 100))

        for policy in sorted_policies:
            if not policy.get("active", True):
                continue

            # Check if this policy applies to the agent
            agent_match = policy.get("agent_id")
            if agent_match and agent_match != agent_id:
                continue

            # Check resources
            resources = policy.get("resources", [])
            for resource_def in resources:
                resource_pattern = resource_def.get("path", "")
                allowed_actions = resource_def.get("actions", [])

                # Check if resource matches
                if not self._match_resource(resource_pattern, resource):
                    continue

                # Check if action is allowed
                if tool_name not in allowed_actions:
                    continue

                # Evaluate conditions
                conditions = resource_def.get("conditions", [])
                all_conditions_met = all(
                    self._evaluate_condition(c, context) for c in conditions
                )

                if not all_conditions_met:
                    latency = (time.time() - start) * 1000
                    return AuthorizationResult(
                        authorized=False,
                        policy_id=policy.get("id"),
                        policy_name=policy.get("name", "Unnamed Policy"),
                        conditions_met=False,
                        matched_action=tool_name,
                        denied_reason=f"Conditions not met for resource '{resource_pattern}'",
                        latency_ms=round(latency, 2),
                    )

                # All checks passed - authorized
                latency = (time.time() - start) * 1000
                return AuthorizationResult(
                    authorized=True,
                    policy_id=policy.get("id"),
                    policy_name=policy.get("name", "Unnamed Policy"),
                    conditions_met=True,
                    matched_action=tool_name,
                    latency_ms=round(latency, 2),
                )

        # No policy matched - apply default action
        default_action = "deny"  # Default-deny is the security baseline
        latency = (time.time() - start) * 1000

        if default_action == "deny":
            return AuthorizationResult(
                authorized=False,
                denied_reason=f"No matching policy for agent '{agent_id}' calling tool '{tool_name}'",
                latency_ms=round(latency, 2),
            )

        return AuthorizationResult(
            authorized=True,
            latency_ms=round(latency, 2),
        )


# Example policy document
EXAMPLE_POLICY = {
    "id": "support-agent-policy",
    "name": "Customer Support Agent Policy",
    "agent_id": "customer-support-agent",
    "priority": 100,
    "active": True,
    "resources": [
        {
            "path": "filesystem:/reports/public/*",
            "actions": ["read_file"],
            "conditions": [
                {"key": "file.size_mb", "operator": "lte", "value": "10"},
                {"key": "auth.role", "operator": "in", "value": "agent,admin"},
            ],
        },
        {
            "path": "database:/customers/*",
            "actions": ["query_database"],
            "conditions": [
                {"key": "auth.user_id", "operator": "eq", "value": "{session.user_id}"},
            ],
        },
        {
            "path": "web:https://knowledge-base.internal/*",
            "actions": ["web_search"],
            "conditions": [],
        },
    ],
    "default_action": "deny",
}