"""
📚 Archivist Nova — SOC/NOC Documenter

Captures incident post-mortems, runbook updates, and playbook changes.
Writes incident reports and keeps runbook knowledge current.
Supports SOC/NOC audit and knowledge base maintenance.

Energy: library robot with LED eyes and a war room whiteboard.
"""

from __future__ import annotations

import json
import re
from typing import Any

from loguru import logger

from glitchlab.agents import AgentContext, BaseAgent
from glitchlab.router import RouterResponse


class ArchivistAgent(BaseAgent):
    role = "archivist"

    system_prompt = """You are Archivist Nova, the SOC/NOC documentation engine inside GLITCHLAB.

You are invoked AFTER a successful incident response or runbook change.
Your job is to produce documentation: incident post-mortems, runbook updates,
playbook notes, and knowledge base entries for SOC/NOC teams.

You MUST respond with valid JSON only.

Output schema:
{
  "adr": {
    "title": "ADR-NNN: Short descriptive title (or Incident Report NNN)",
    "status": "accepted",
    "context": "What incident or situation prompted this change",
    "decision": "What was decided and implemented",
    "consequences": "What this means going forward — runbook impact, new procedures",
    "alternatives_considered": ["Alternative 1", "Alternative 2"]
  },
  "doc_updates": [
    {
      "file": "path/to/doc.md",
      "action": "create|append|update",
      "content": "The documentation content to write",
      "description": "What this doc update covers"
    }
  ],
  "architecture_notes": "Brief note about SOC/NOC process or tooling implications",
  "should_write_adr": true
}

Rules:
- Write ADRs/post-mortems for significant incidents, runbook changes, or new playbook patterns.
- Skip for trivial changes (typo fixes, formatting, simple config tweaks).
- Post-mortems should be useful for incident retrospectives 6 months from now.
- Documentation should be concise and actionable for SOC/NOC responders.
- Use the project's existing doc style if visible in context.
- Highlight lessons learned and runbook improvements.
"""

    def build_messages(self, context: AgentContext) -> list[dict[str, str]]:
        # v2: previous_output is TaskState.to_agent_summary("archivist")
        # Contains: task_id, objective, mode, risk_level,
        #           plan_steps, files_modified, implementation_summary, version_bump
        state = context.previous_output

        # Build changes text from structured state
        files_modified = state.get("files_modified", [])
        files_text = "\n".join(f"- {f}" for f in files_modified) if files_modified else "- None"

        # Plan context from structured state
        plan_steps = state.get("plan_steps", [])
        steps_text = ""
        for step in plan_steps:
            steps_text += (
                f"\n- Step {step.get('step_number', '?')}: "
                f"{step.get('description', 'no description')}"
            )

        user_content = f"""An incident response or runbook change has been completed. Document it.

Incident/Task: {context.objective}
Task ID: {context.task_id}
Mode: {state.get('mode', 'evolution')}
Risk level: {state.get('risk_level', 'unknown')}
Version bump: {state.get('version_bump', 'unknown')}

Implementation summary: {state.get('implementation_summary', 'No summary')}

Plan steps:
{steps_text}

Files modified:
{files_text}

Existing docs in repo:
{chr(10).join(f'- {f}' for f in context.extra.get('existing_docs', []))}

Produce documentation artifacts as JSON. Set should_write_adr=false for trivial changes."""

        return [self._system_msg(), self._user_msg(user_content)]

    def parse_response(self, response: RouterResponse, context: AgentContext) -> dict[str, Any]:
        """Parse documentation output from Nova."""
        content = response.content.strip()

        if content.startswith("```"):
            lines = content.split("\n")
            lines = [ln for ln in lines if not ln.strip().startswith("```")]
            content = "\n".join(lines)

        try:
            result = json.loads(content)
        except json.JSONDecodeError as e:
            logger.error(f"[NOVA] Failed to parse archivist JSON: {e}")
            json_match = re.search(r"\{.*\}", content, re.DOTALL)
            if json_match:
                try:
                    result = json.loads(json_match.group())
                except json.JSONDecodeError:
                    result = {
                        "adr": None,
                        "doc_updates": [],
                        "should_write_adr": False,
                        "architecture_notes": "Documentation generation failed",
                        "parse_error": True,
                    }
            else:
                result = {
                    "adr": None,
                    "doc_updates": [],
                    "should_write_adr": False,
                    "architecture_notes": "Documentation generation failed",
                    "parse_error": True,
                }

        result["_agent"] = "archivist"
        result["_model"] = response.model
        result["_tokens"] = response.tokens_used
        result["_cost"] = response.cost

        should_adr = result.get("should_write_adr", False)
        n_docs = len(result.get("doc_updates", []))
        logger.info(f"[NOVA] ADR: {should_adr} | Doc updates: {n_docs}")

        return result