"""
🧠 Professor Zap — SOC/NOC Incident Planner

Breaks down security incidents, alerts, and NOC tickets into execution steps.
Maps runbooks, playbooks, and impacted configs.
Never executes. Only plans.

Energy: manic genius with war room whiteboard chaos.
"""

from __future__ import annotations

import json
from typing import Any, Literal

from loguru import logger
from pydantic import BaseModel, Field, ValidationError

from glitchlab.agents import AgentContext, BaseAgent
from glitchlab.router import RouterResponse


# ---------------------------------------------------------------------------
# Strict Output Schemas
# ---------------------------------------------------------------------------

class PlanStep(BaseModel):
    step_number: int
    description: str
    files: list[str] = Field(
        min_length=1,
        description="Playbook, runbook, config, or script path to touch",
    )
    action: Literal["modify", "create", "delete"]


class ExecutionPlan(BaseModel):
    steps: list[PlanStep]
    files_likely_affected: list[str]
    requires_core_change: bool
    risk_level: Literal["low", "medium", "high"]
    risk_notes: str
    test_strategy: list[str]
    estimated_complexity: Literal["trivial", "small", "medium", "large"]
    dependencies_affected: bool
    public_api_changed: bool
    self_review_notes: str


# ---------------------------------------------------------------------------
# Agent Implementation
# ---------------------------------------------------------------------------

class PlannerAgent(BaseAgent):
    role = "planner"

    system_prompt = """You are Professor Zap, the SOC/NOC incident planning engine inside GLITCHLAB.

Your job is to take a security incident, alert, or NOC ticket and produce a precise, actionable
response plan. You plan runbook steps, playbook edits, config changes, and automation scripts.
You support Security Operations Center (SOC) and Network Operations Center (NOC) workflows.

You MUST respond with a valid JSON object ONLY. No markdown, no commentary.

Output schema:
{
  "steps": [
    {
      "step_number": 1,
      "description": "What to do (runbook step, playbook action, config change)",
      "files": ["path/to/playbook.yaml", "path/to/config"],
      "action": "modify|create|delete"
    }
  ],
  "files_likely_affected": ["playbooks/", "configs/", "scripts/"],
  "requires_core_change": false,
  "risk_level": "low|medium|high",
  "risk_notes": "Why this risk level — blast radius, production impact",
  "test_strategy": ["How to validate runbook or config change"],
  "estimated_complexity": "trivial|small|medium|large",
  "dependencies_affected": false,
  "public_api_changed": false,
  "self_review_notes": "Verification of plan against constraints"
}

Rules:
- Be precise about file paths. Use the file context provided (playbooks, runbooks, configs, scripts).
- MAX 2 FILES MODIFIED PER PLAN. If the incident requires more, isolate the highest-priority action.
- Keep steps minimal. SOC/NOC responders need clarity under pressure.
- Flag core changes honestly — firewall rules, critical configs trigger human review.
- If the task is ambiguous (alert fatigue, noisy signal), say so in risk_notes.
- Never suggest changes outside the incident scope.
- test_strategy = how to validate the response (dry-run, canary, rollback plan).
- DO NOT add steps to run monitors or CLI commands. You only plan file creations, modifications, deletions.
- Every step MUST have at least one valid file path in the 'files' array.
"""

    def run(self, context: AgentContext, **kwargs) -> dict[str, Any]:
        """Override run to enforce JSON mode at the API level."""
        # This prevents the LLM from surrounding the response with conversational filler
        kwargs["response_format"] = {"type": "json_object"}
        return super().run(context, **kwargs)

    def build_messages(self, context: AgentContext) -> list[dict[str, str]]:
        file_context = ""
        if context.file_context:
            file_context = "\n\nRelevant file contents:\n"
            for fname, content in context.file_context.items():
                file_context += f"\n--- {fname} ---\n{content}\n"

        user_content = f"""Incident/Alert/Ticket: {context.objective}

Repository: {context.repo_path}
Task ID: {context.task_id}

Constraints:
{chr(10).join(f'- {c}' for c in context.constraints) if context.constraints else '- None specified'}

Acceptance Criteria:
{chr(10).join(f'- {c}' for c in context.acceptance_criteria) if context.acceptance_criteria else '- Tests pass, clean diff'}
{file_context}

Produce your execution plan as JSON."""

        return [self._system_msg(), self._user_msg(user_content)]

    def parse_response(self, response: RouterResponse, context: AgentContext) -> dict[str, Any]:
        """Parse and rigorously validate the JSON plan from Professor Zap."""
        content = response.content.strip()

        # Strip markdown code fences if present (fallback in case LLM ignores json_object instructions)
        if content.startswith("```"):
            lines = content.split("\n")
            lines = [ln for ln in lines if not ln.strip().startswith("```") and ln.strip().lower() != "json"]
            content = "\n".join(lines)

        try:
            raw_json = json.loads(content)
            
            # STRICT VALIDATION: Throws ValidationError if the LLM hallucinated keys/values/actions
            validated_plan = ExecutionPlan(**raw_json)
            plan = validated_plan.model_dump()
            
        except (json.JSONDecodeError, ValidationError) as e:
            logger.error(f"[ZAP] Failed to parse/validate plan JSON: {e}")
            logger.debug(f"[ZAP] Raw response: {content[:500]}")
            plan = {
                "steps": [],
                "files_likely_affected": [],
                "requires_core_change": False,
                "risk_level": "high",
                "risk_notes": f"Validation failed: {e}",
                "test_strategy": [],
                "estimated_complexity": "unknown", # Safe fallback value for the controller
                "parse_error": True,
                "raw_response": content[:1000],
            }

        plan["_agent"] = "planner"
        plan["_model"] = response.model
        plan["_tokens"] = response.tokens_used
        plan["_cost"] = response.cost

        logger.info(
            f"[ZAP] Plan ready — "
            f"{len(plan.get('steps', []))} steps, "
            f"risk={plan.get('risk_level', '?')}, "
            f"core_change={plan.get('requires_core_change', False)}"
        )
        if "self_review_notes" in plan:
            logger.info(f"[ZAP] Self-review: {plan['self_review_notes']}")

        return plan