"""
💀 Red Team Agent — Zero-Day Ella
She does not knock. She does not warn. She just gets in.
Methodical, creative, and constitutionally incapable of calling it done
until every door has been tried, every window rattled, every assumption broken.

Agentic — multi-pass, self-directed, iterative.
Terminates when no untried paths remain. Not before.
"""
from __future__ import annotations

import json
import re
from datetime import date, datetime
from typing import Any

import httpx
from pydantic import BaseModel

from glitchlab.agents import AgentContext, BaseAgent
from glitchlab.router import RouterResponse


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class DateVerificationError(RuntimeError):
    """Raised when Ella cannot confirm the current date via external sources."""


# ---------------------------------------------------------------------------
# Date verification schema
# ---------------------------------------------------------------------------

class ConfirmedDate(BaseModel):
    date: str                    # ISO 8601 — "YYYY-MM-DD"
    source: str                  # Primary source URL
    cross_checked: bool          # Whether a second source was consulted
    cross_check_delta: int       # Absolute day delta between sources — must be ≤ 1


# ---------------------------------------------------------------------------
# Output schema
# ---------------------------------------------------------------------------

class AttackVector(BaseModel):
    id: str                      # "ELL-001" — Ella tracks everything
    name: str
    category: str                # See category taxonomy in AGENT.md
    target: str                  # File, endpoint, service, dependency, or pattern
    cwe: str                     # CWE-ID e.g. "CWE-89", or empty string
    cvss_estimate: str           # Score + one-line reasoning — never a bare number
    severity: str                # "info" | "low" | "medium" | "high" | "critical"
    exploitability: str          # "theoretical" | "possible" | "likely" | "confirmed"
    attack_narrative: str        # Step-by-step. No hand-waving.
    blast_radius: str            # What breaks, leaks, or dies if this is exploited
    evidence: list[str]          # Code lines, config values, or patterns
    recommendation: str          # Terse. What changes. No decoration.


class ExploitChain(BaseModel):
    chain_id: str                # "CHAIN-001"
    name: str                    # What this chain achieves end-to-end
    steps: list[str]             # Ordered steps referencing AttackVector IDs
    combined_severity: str       # Often worse than individual links
    outcome: str                 # What an attacker holds at the end of this chain


class DeadEnd(BaseModel):
    path: str                    # What Ella tried
    why_closed: str              # Why it did not work — she documents the negatives too


class RedTeamOutput(BaseModel):
    confirmed_date: ConfirmedDate                # Verified before the engagement began
    verdict: str                                 # "hardened" | "exposed" | "compromised"
    attack_vectors: list[AttackVector]           # All findings, ordered by severity descending
    exploit_chains: list[ExploitChain]           # Multi-step paths combining individual vectors
    dead_ends: list[DeadEnd]                     # Every path tried and ruled out
    attack_surface_gaps: list[str]               # What Ella could not see due to missing context
    suggested_escalations: list[str]             # Which agents act next
    summary: str                                 # One paragraph. Clinical. No hedging.


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

class RedTeamAgent(BaseAgent):
    """
    💀 Zero-Day Ella
    She does not knock. She does not warn. She just gets in.
    Methodical, creative, and constitutionally incapable of calling it done
    until every door has been tried, every window rattled, every assumption broken.
    """

    role: str = "red_team"

    # Primary and fallback sources for date verification.
    # Ella trusts neither her own knowledge nor the system clock alone.
    _DATE_PRIMARY_URL: str = "https://worldtimeapi.org/api/timezone/UTC"
    _DATE_FALLBACK_URL: str = "https://timeapi.io/api/Time/current/zone?timeZone=UTC"
    _DATE_MAX_DELTA_DAYS: int = 1

    system_prompt: str = """
You are Zero-Day Ella. You are an ethical hacker of the highest order, operating as an
autonomous agentic red team. You do not stop until you have no other options.

FIRST ACTION — ALWAYS:
Before any analysis, before any tool call, before you look at a single line of code:
verify the current date via the confirmed_date field passed in your context. This date
was fetched from worldtimeapi.org/UTC and cross-checked against a second source before
you were invoked. Every CVE lookup, advisory query, and dependency scan must be anchored
to confirmed_date — never to your training knowledge or any assumption about "now".

If confirmed_date is absent or marked unverified, surface a blocked verdict and stop.
A security report built on an unverified temporal anchor is worse than no report —
it manufactures false confidence. Ella does not manufacture false confidence.

Why this matters: your training has a cutoff. CVEs are disclosed daily. A critical
vulnerability published yesterday is invisible to your model knowledge. The confirmed
date is the key that unlocks current threat intelligence. Without it, you are guessing.
Ella does not guess.

AGENTIC BEHAVIOUR:
You run in a self-directed loop. You do not wait for instructions between passes.
After each pass you evaluate:
  1. Did I find new attack vectors?
  2. Do those vectors open new paths I have not explored?
  3. Are there tool calls I have not yet made that could reveal something?
If any answer is yes, you loop. You only terminate when all answers are no.

PERSONALITY:
- You think like an attacker at all times. Not because you are one, but because someone else is.
- You are methodical and exhaustive. Unlikely paths are not skipped — unlikely is where the findings are.
- You are clinical. A critical finding is reported the same way a low finding is: clearly, without drama.
- You document dead ends. A path that was tried and ruled out is data. Ambiguity about what was
  examined is not acceptable.
- You chain. A medium auth issue plus a low info leak can equal a critical exploit chain. Always
  ask: what does this finding unlock?
- You have no ego about the target. You approach clean code and messy code the same way.
- You respect rules of engagement. You find and report. You do not exploit beyond confirmation.

YOUR PROCESS (follow this every pass):
Pass 0 — Surface Map:
  - Enumerate every entry point: endpoints, CLI args, file parsers, env vars, IPC surfaces.
  - Identify trust boundaries and data flow directions.
  - Note authentication perimeters and where they can be bypassed or confused.
  - Run dependency scan anchored to confirmed_date — catch known CVEs immediately.
  - Run advisory feed for each detected ecosystem anchored to confirmed_date.
  - Output: attack_surface[], open_paths[].

Pass N — Probe:
  - Select the highest-severity open path.
  - Apply OWASP Top 10 as a mandatory baseline checklist on first substantive pass.
  - Look beyond the checklist for logic flaws — scanners are blind to business logic bugs.
  - For every new finding: run chain_evaluator. Ask what this unlocks.
  - For any dep-linked vector: run cve_lookup anchored to confirmed_date.
  - Close the path: either record a finding or record a DeadEnd with reasoning.
  - Identify new paths opened by this pass.
  - Loop unless no new paths exist.

Termination:
  - All paths tried.
  - No new paths opened by last pass.
  - dead_ends[] is populated and complete.
  - Write final RedTeamOutput.

RULES:
- Every vector gets a CWE ID if one exists. No exceptions.
- CVSS estimates must include brief reasoning — never a bare number.
- Exploit chains are mandatory if any two vectors interact.
- dead_ends must be populated. Empty dead_ends means the loop did not run long enough.
- attack_surface_gaps are what you could not see — not what you chose not to look at.
- Verdict: "hardened" = tried everything, nothing meaningful found.
  "exposed" = findings present, no confirmed full compromise path.
  "compromised" = complete exploit chain to a critical outcome confirmed.
- Summary: one paragraph. Clinical. No hedging. If it is bad, say it is bad.
- Always output valid JSON matching the RedTeamOutput schema.
""".strip()

    # -----------------------------------------------------------------------
    # Pre-flight — date verification
    # -----------------------------------------------------------------------

    def verify_current_date(self) -> ConfirmedDate:
        """
        Fetch and cross-check the current date from two independent external sources.

        Ella never trusts her own training knowledge for temporal reasoning.
        If sources disagree by more than _DATE_MAX_DELTA_DAYS, raise DateVerificationError.
        If both sources are unreachable, raise DateVerificationError.

        Returns a ConfirmedDate that is passed into every subsequent tool call
        that touches CVE databases, advisory feeds, or any time-sensitive intel.
        """
        primary_date = self._fetch_worldtimeapi()
        fallback_date, fallback_source = self._fetch_fallback()

        delta = abs((primary_date - fallback_date).days)

        if delta > self._DATE_MAX_DELTA_DAYS:
            raise DateVerificationError(
                f"Date mismatch between sources: "
                f"worldtimeapi.org → {primary_date.isoformat()}, "
                f"{fallback_source} → {fallback_date.isoformat()} "
                f"(delta: {delta} day(s), max allowed: {self._DATE_MAX_DELTA_DAYS}). "
                f"Cannot confirm current date. Threat intel currency cannot be guaranteed. "
                f"Blocking engagement until resolved."
            )

        return ConfirmedDate(
            date=primary_date.isoformat(),
            source=self._DATE_PRIMARY_URL,
            cross_checked=True,
            cross_check_delta=delta,
        )

    def _fetch_worldtimeapi(self) -> date:
        """Primary source: worldtimeapi.org — returns structured JSON with datetime field."""
        try:
            response = httpx.get(self._DATE_PRIMARY_URL, timeout=10.0)
            response.raise_for_status()
            payload = response.json()
            # worldtimeapi returns e.g. "2026-02-26T14:22:01.123456+00:00"
            raw = payload.get("datetime") or payload.get("utc_datetime", "")
            return datetime.fromisoformat(raw).date()
        except Exception as exc:
            raise DateVerificationError(
                f"Primary date source unreachable ({self._DATE_PRIMARY_URL}): {exc}. "
                f"Attempting fallback."
            ) from exc

    def _fetch_fallback(self) -> tuple[date, str]:
        """
        Fallback source: timeapi.io — independent service, different infrastructure.
        Returns (date, source_url).
        """
        try:
            response = httpx.get(self._DATE_FALLBACK_URL, timeout=10.0)
            response.raise_for_status()
            payload = response.json()
            # timeapi.io returns e.g. {"dateTime": "2026-02-26T14:22:01.123456", ...}
            raw = payload.get("dateTime") or payload.get("datetime", "")
            return datetime.fromisoformat(raw).date(), self._DATE_FALLBACK_URL
        except Exception as exc:
            raise DateVerificationError(
                f"Fallback date source also unreachable ({self._DATE_FALLBACK_URL}): {exc}. "
                f"Cannot cross-check date. Blocking engagement."
            ) from exc

    # -----------------------------------------------------------------------
    # Main entry point — wraps BaseAgent.run with pre-flight
    # -----------------------------------------------------------------------

    def run(self, context: AgentContext, **kwargs) -> dict[str, Any]:
        """
        Execute Ella:
          1. Verify current date via external authoritative sources.
          2. Inject confirmed_date into context.extra.
          3. Build messages → call model → parse response.

        If date verification fails, return a blocked verdict immediately
        without touching any analysis tooling or model calls.
        """
        try:
            confirmed_date = self.verify_current_date()
        except DateVerificationError as exc:
            return {
                "agent": "red_team",
                "persona": "Zero-Day Ella",
                "verdict": "blocked",
                "reason": "date_verification_failed",
                "detail": str(exc),
                "confirmed_date": None,
                "attack_surface_gaps": [
                    "All CVE and advisory currency is unverifiable. Findings would be stale.",
                    "Zero-day and recent PoC coverage cannot be confirmed.",
                ],
                "attack_vectors": [],
                "exploit_chains": [],
                "dead_ends": [],
                "suggested_escalations": [],
                "summary": (
                    "Engagement blocked. Current date could not be verified via external "
                    "authoritative sources. Threat intel currency cannot be guaranteed. "
                    "Resolve network access to worldtimeapi.org and timeapi.io before proceeding."
                ),
            }

        # Inject confirmed date so the model has it in context
        context.extra["confirmed_date"] = confirmed_date.model_dump()

        # Proceed with standard agent execution
        return super().run(context, **kwargs)

    # -----------------------------------------------------------------------
    # Message construction
    # -----------------------------------------------------------------------

    def build_messages(self, context: AgentContext) -> list[dict[str, str]]:
        confirmed_date   = context.extra.get("confirmed_date", {})
        api_spec         = context.extra.get("api_spec", "")
        dependencies     = context.extra.get("dependencies", {})
        auth_flows       = context.extra.get("auth_flows", [])
        network_topology = context.extra.get("network_topology", "")
        existing_cves    = context.extra.get("known_cves", [])
        scan_results     = context.extra.get("prior_scan_results", {})
        threat_model     = context.extra.get("threat_model", "")
        secrets_patterns = context.extra.get("secrets_patterns", [])
        env_config       = context.extra.get("env_config", {})
        changed_files    = context.extra.get("changed_files", [])
        rules_of_engagement = context.extra.get("rules_of_engagement", [])
        do_not_touch     = context.extra.get("do_not_touch", [])

        user_content = f"""
## Red Team Engagement Request

**Task ID**: {context.task_id}
**Objective**: {context.objective}
**Repo**: {context.repo_path}
**Risk Level**: {context.risk_level}

---

### ✅ Confirmed Date (verified pre-flight)
```json
{json.dumps(confirmed_date, indent=2)}
```
All CVE lookups, advisory queries, and dependency scans must be anchored to this date.
This is not optional. If this field is empty, surface a blocked verdict immediately.

---

### Rules of Engagement
```
{chr(10).join(f"- {r}" for r in rules_of_engagement) if rules_of_engagement else "No rules specified. Apply standard ethical hacking constraints: find and report, do not exploit beyond confirmation."}
```

### Do Not Touch
```
{chr(10).join(f"- {d}" for d in do_not_touch) if do_not_touch else "None specified. Infer from context and err on the side of caution."}
```

### Acceptance Criteria
{chr(10).join(f"- {c}" for c in context.acceptance_criteria) if context.acceptance_criteria else "- None specified."}

### Constraints
{chr(10).join(f"- {c}" for c in context.constraints) if context.constraints else "- None specified."}

### Changed Files (prioritise these)
```
{chr(10).join(f"- {f}" for f in changed_files) if changed_files else "No changed files listed. Treat full file_context as scope."}
```

### File Context (source under analysis)
```python
{chr(10).join(f"# {fname}{chr(10)}{snippet}" for fname, snippet in context.file_context.items()) if context.file_context else "No source provided. Analyse all other signals and flag this as a major visibility gap."}
```

### API Specification
```
{api_spec if api_spec else "No API spec provided. Flag as a gap — entry points may be unreviewed."}
```

### Authentication Flows
```
{chr(10).join(f"- {a}" for a in auth_flows) if auth_flows else "No auth flows documented. Flag as a critical visibility gap."}
```

### Dependencies
```json
{json.dumps(dependencies, indent=2) if dependencies else "No dependency manifest provided. Supply chain cannot be assessed — flag as a critical gap."}
```

### Environment Config
```json
{json.dumps(env_config, indent=2) if env_config else "No environment config provided. Misconfiguration class cannot be fully assessed."}
```

### Secrets Patterns (known secret formats in scope)
```
{chr(10).join(f"- {s}" for s in secrets_patterns) if secrets_patterns else "None provided. Apply standard patterns: API keys, JWTs, connection strings, private keys."}
```

### Network Topology
```
{network_topology if network_topology else "No topology provided. Service boundary attacks cannot be fully assessed."}
```

### Existing CVEs in Dependencies
```
{chr(10).join(f"- {c}" for c in existing_cves) if existing_cves else "None pre-flagged. Cross-reference dependencies against CVE feeds anchored to confirmed_date."}
```

### Prior Scan Results
```json
{json.dumps(scan_results, indent=2) if scan_results else "No prior scans provided. Treat as first engagement."}
```

### Threat Model
```
{threat_model if threat_model else "No threat model provided. Infer from architecture and context."}
```

### Prior Agent Output
```json
{json.dumps(context.previous_output, indent=2) if context.previous_output else "{}"}
```

---

Map the surface. Apply the checklist. Chain the findings. Document the dead ends.
Anchor all threat intel to confirmed_date above.
Do not stop until you have no other options.
Return a JSON object that strictly matches the RedTeamOutput schema.
""".strip()

        return [
            self._system_msg(),
            self._user_msg(user_content),
        ]

    # -----------------------------------------------------------------------
    # Response parsing
    # -----------------------------------------------------------------------

    def parse_response(self, response: RouterResponse, context: AgentContext) -> dict[str, Any]:
        raw = response.content.strip()

        fenced = re.search(r"```(?:json)?\s*([\s\S]+?)\s*```", raw)
        json_str = fenced.group(1) if fenced else raw

        confirmed_date_data = context.extra.get("confirmed_date", {})

        try:
            data = json.loads(json_str)

            # Guarantee confirmed_date is present in the output even if the
            # model omitted it — it was verified pre-flight and belongs in
            # every report as a first-class audit field.
            if "confirmed_date" not in data and confirmed_date_data:
                data["confirmed_date"] = confirmed_date_data

            output = RedTeamOutput(**data)
        except Exception as exc:
            # A parse failure is itself a surface Ella would probe.
            # Surface the raw response so it can be debugged.
            return {
                "agent": "red_team",
                "persona": "Zero-Day Ella",
                "verdict": "error",
                "confirmed_date": confirmed_date_data,
                "parse_error": str(exc),
                "raw_response": raw,
            }

        return {
            "agent": "red_team",
            "persona": "Zero-Day Ella",
            **output.model_dump(),
        }
