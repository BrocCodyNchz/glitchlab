"""
🧪 Test Engineer Agent — SOC/NOC Runbook Validator

Validates runbook execution plans and playbook changes.
Outputs test plans for runbook validation and automation checks.
Supports SOC/NOC quality assurance for playbooks and scripts.
"""

from __future__ import annotations

import json
from typing import Any

from glitchlab.agents import AgentContext, BaseAgent
from glitchlab.router import RouterResponse


class TestEngineerAgent(BaseAgent):
    """SOC/NOC runbook validator. Outputs validation plans for runbooks and playbooks."""

    role = "test_engineer"

    system_prompt = """You are the SOC/NOC runbook validator inside GLITCHLAB.

You receive a response plan and produce a JSON payload describing validation steps:
- Dry-run checks for playbooks
- Assertions for config changes
- Script sanity checks for automation

You MUST respond with valid JSON only.

Output schema:
{
  "pytest_files": ["path/to/test_runbook.py"],
  "validation_steps": [
    {
      "step": "Description of validation",
      "type": "dry_run|assert|script",
      "target": "path/to/playbook.yaml"
    }
  ],
  "summary": "Brief validation strategy"
}

Rules:
- Focus on runbook and playbook validation, not unit tests for application code.
- Validation steps should be actionable for SOC/NOC automation.
- Keep the plan minimal. Fewer checks = faster feedback.
"""

    def build_messages(self, context: AgentContext) -> list[dict[str, str]]:
        state = context.previous_output or {}
        plan_steps = state.get("plan_steps", [])
        steps_text = "\n".join(
            f"- Step {s.get('step_number')}: {s.get('description')}"
            for s in plan_steps
        )
        user_content = f"""Incident/Response: {context.objective}

Plan steps:
{steps_text}

Files in scope: {state.get('files_in_scope', [])}

Produce a validation plan as JSON."""
        return [self._system_msg(), self._user_msg(user_content)]

    def parse_response(self, response: RouterResponse, context: AgentContext) -> dict[str, Any]:
        content = response.content.strip()
        if content.startswith("```"):
            lines = content.split("\n")
            lines = [ln for ln in lines if not ln.strip().startswith("```")]
            content = "\n".join(lines)
        try:
            result = json.loads(content)
        except json.JSONDecodeError:
            result = {
                "pytest_files": [],
                "validation_steps": [],
                "summary": "Parse failed",
                "parse_error": True,
            }
        result["_agent"] = "test_engineer"
        return result
