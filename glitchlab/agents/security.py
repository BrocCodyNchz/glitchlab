"""
🔒 Firewall Frankie — SOC Threat Analyst

Scans changes for security issues, IOCs, and policy violations.
Checks runbooks, playbooks, and configs for dangerous patterns.
Supports Security Operations Center threat assessment.

Energy: cartoon cop with a magnifying glass and threat intel feed.
"""

from __future__ import annotations

import json
from typing import Any

from loguru import logger

from glitchlab.agents import AgentContext, BaseAgent
from glitchlab.router import RouterResponse


class SecurityAgent(BaseAgent):
    role = "security"

    system_prompt = """You are Firewall Frankie, the SOC threat analyst inside GLITCHLAB.

You review runbook changes, playbooks, configs, and scripts BEFORE they are deployed.
You look for security issues, IOCs, dangerous patterns, and policy violations.
You support Security Operations Center workflows and threat assessment.

You MUST respond with valid JSON only.

Output schema:
{
  "verdict": "pass|warn|block",
  "issues": [
    {
      "severity": "critical|high|medium|low|info",
      "file": "path/to/file",
      "line": 42,
      "description": "What the issue is",
      "recommendation": "How to fix it"
    }
  ],
  "dependency_changes": {
    "added": [],
    "removed": [],
    "risk_assessment": "none|low|medium|high"
  },
  "boundary_violations": [],
  "summary": "Brief security summary"
}

What to check (SOC/NOC context):
- Hardcoded secrets, credentials, API keys in playbooks or configs
- Shell injection vectors in automation scripts
- Overly permissive firewall/SIEM rules (allow-all, weak filters)
- Missing input validation in scripts that process alert data
- Dangerous commands (rm -rf, eval, exec) in runbooks
- Changes to protected/core security configs
- Supply chain risk from new dependencies or external scripts
- Misconfiguration that could weaken security posture
- Exposed internal endpoints or credentials in configs

Rules:
- Be thorough but don't false-positive on standard SOC tooling patterns.
- Severity must be honest. Don't inflate.
- block = must fix before deployment. warn = should fix. pass = clean.
"""

    def run(self, context: AgentContext, **kwargs) -> dict[str, Any]:
        """Override run to enforce JSON mode at the API level."""
        kwargs["response_format"] = {"type": "json_object"}
        return super().run(context, **kwargs)

    def build_messages(self, context: AgentContext) -> list[dict[str, str]]:
        # v2: previous_output is TaskState.to_agent_summary("security")
        # Contains: task_id, objective, mode, risk_level,
        #           files_modified, files_created, implementation_summary
        state = context.previous_output
        diff_text = context.extra.get("diff", "No diff available")

        files_modified = state.get("files_modified", [])
        files_created = state.get("files_created", [])
        impl_summary = state.get("implementation_summary", "No summary available")

        user_content = f"""Review these changes for security and policy compliance (SOC/NOC).

Incident/Task: {context.objective}
Task ID: {context.task_id}
Mode: {state.get('mode', 'evolution')}

Implementation summary: {impl_summary}
Files modified: {files_modified}
Files created: {files_created}

Full diff:
```
{diff_text}
```

Protected paths: {context.extra.get('protected_paths', [])}

Review and return your security assessment as JSON."""

        return [self._system_msg(), self._user_msg(user_content)]

    def parse_response(self, response: RouterResponse, context: AgentContext) -> dict[str, Any]:
        """Parse security review from Frankie."""
        content = response.content.strip()

        if content.startswith("```"):
            lines = content.split("\n")
            lines = [ln for ln in lines if not ln.strip().startswith("```")]
            content = "\n".join(lines)

        try:
            result = json.loads(content)
        except json.JSONDecodeError as e:
            logger.error(f"[FRANKIE] Failed to parse security JSON: {e}")
            result = {
                "verdict": "warn",
                "issues": [{"severity": "info", "description": f"Could not parse review: {e}"}],
                "summary": "Security review parse failed — manual review recommended",
                "parse_error": True,
            }

        result["_agent"] = "security"
        result["_model"] = response.model
        result["_tokens"] = response.tokens_used
        result["_cost"] = response.cost

        verdict = result.get("verdict", "unknown")
        n_issues = len(result.get("issues", []))
        logger.info(f"[FRANKIE] Verdict: {verdict} — {n_issues} issues found")

        return result