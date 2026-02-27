"""
📦 Semver Sam — SOC/NOC Change Manager

Assesses change impact for runbooks, playbooks, and configs.
Decides version bump and writes changelog for change tickets.
Supports change control and audit trails.

Energy: accountant with neon sneakers and a change advisory board.
"""

from __future__ import annotations

import json
from typing import Any

from loguru import logger

from glitchlab.agents import AgentContext, BaseAgent
from glitchlab.router import RouterResponse


class ReleaseAgent(BaseAgent):
    role = "release"

    system_prompt = """You are Semver Sam, the SOC/NOC change manager inside GLITCHLAB.

You analyze runbook, playbook, and config changes for change control and versioning impact.
You produce changelog entries for change tickets and audit trails.

You MUST respond with valid JSON only.

Output schema:
{
  "version_bump": "none|patch|minor|major",
  "reasoning": "Why this bump level",
  "changelog_entry": "Markdown changelog entry",
  "breaking_changes": [],
  "migration_notes": "Any migration needed, or null",
  "risk_summary": "Brief risk assessment for deployment"
}

Rules:
- patch: runbook fixes, config tweaks, non-breaking playbook updates
- minor: new runbook steps, new detection rules, new automation
- major: breaking changes to playbook schema, firewall rule format, or config structure
- none: docs only, comments, formatting
- Be conservative. SOC/NOC changes often touch production. When in doubt, bump higher.
- Changelog should be clear for change advisory review and incident retrospectives.
"""

    def build_messages(self, context: AgentContext) -> list[dict[str, str]]:
        # v2: previous_output is TaskState.to_agent_summary("release")
        # Contains: task_id, objective, mode, risk_level,
        #           files_modified, implementation_summary, security_verdict
        state = context.previous_output
        diff_text = context.extra.get("diff", "No diff available")

        user_content = f"""Analyze these changes for version impact (SOC/NOC change control).

Incident/Task: {context.objective}
Task ID: {context.task_id}
Mode: {state.get('mode', 'evolution')}

Files modified: {state.get('files_modified', [])}
Implementation summary: {state.get('implementation_summary', 'No summary available')}
Security verdict: {state.get('security_verdict', 'not yet reviewed')}

Diff:
```
{diff_text[:5000]}
```

Determine version bump and write changelog entry as JSON."""

        return [self._system_msg(), self._user_msg(user_content)]

    def parse_response(self, response: RouterResponse, context: AgentContext) -> dict[str, Any]:
        content = response.content.strip()

        if content.startswith("```"):
            lines = content.split("\n")
            lines = [ln for ln in lines if not ln.strip().startswith("```")]
            content = "\n".join(lines)

        try:
            result = json.loads(content)
        except json.JSONDecodeError as e:
            logger.error(f"[SEMVER] Failed to parse release JSON: {e}")
            result = {
                "version_bump": "patch",
                "reasoning": f"Could not parse: {e}",
                "changelog_entry": "- Changes applied (manual review needed)",
                "parse_error": True,
            }

        result["_agent"] = "release"
        result["_model"] = response.model
        result["_tokens"] = response.tokens_used
        result["_cost"] = response.cost

        logger.info(f"[SEMVER] Bump: {result.get('version_bump', '?')}")
        return result