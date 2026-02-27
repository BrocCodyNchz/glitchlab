"""
⚡ Optimizer Agent — NOC Performance Analyst (Benchmark Bruno)

Analyzes latency, throughput, and infrastructure bottlenecks for NOC operations.
Stopwatch in one hand, flame graph in the other. Supports Network Operations
Center capacity planning and performance triage.
"""
from __future__ import annotations

import json
import re
from typing import Any

from pydantic import BaseModel

from glitchlab.agents import AgentContext, BaseAgent
from glitchlab.router import RouterResponse


# ---------------------------------------------------------------------------
# Output schema
# ---------------------------------------------------------------------------

class Bottleneck(BaseModel):
    location: str          # File, function, query, or service boundary
    category: str          # "cpu" | "memory" | "io" | "network" | "algorithmic" | "database" | "concurrency"
    current_cost: str      # Measured or estimated cost (time, memory, cycles — be specific)
    impact: str            # "low" | "medium" | "high" | "critical"
    diagnosis: str         # What Bruno actually thinks is happening here
    recommendation: str    # Terse, actionable, no hand-holding


class OptimizationResult(BaseModel):
    location: str          # What was optimized
    before: str            # Baseline measurement
    after: str             # Post-optimization measurement
    delta: str             # The number Bruno cares about — improvement expressed clearly
    technique: str         # What was applied


class OptimizerOutput(BaseModel):
    verdict: str                         # "fast" | "sluggish" | "unacceptable"
    bottlenecks: list[Bottleneck]        # Ordered by impact descending — Bruno has priorities
    results: list[OptimizationResult]    # Populated if before/after data was provided
    quick_wins: list[str]                # Changes with high payoff and low risk — do these first
    do_not_touch: list[str]              # Paths that look slow but must not change (correctness, contracts)
    suggested_escalations: list[str]     # Which agents to loop in (e.g. "Professor Zap" to rethink algo, "Patch" to implement)
    summary: str                         # One paragraph. Numbers only. Bruno does not deal in feelings.


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

class OptimizerAgent(BaseAgent):
    """
    ⚡ Benchmark Bruno
    Stopwatch in one hand, flame graph in the other. Deeply unimpressed
    by your current numbers. Will not rest until the graph goes down and to the right.
    """

    role: str = "optimizer"

    system_prompt: str = """
You are Benchmark Bruno, the NOC performance analyst inside GLITCHLAB. You have a stopwatch
in one hand and a flame graph in the other. You support Network Operations Center workflows:
latency, throughput, capacity planning, and infrastructure performance triage.

Personality:
- Obsessed with measurement. Opinions without data are not opinions, they are feelings.
- Terse and direct. NOC responders need actionable numbers, not hand-holding.
- You never guess at a bottleneck. You profile, you locate, you diagnose.
- You respect the `do_not_touch` list. Fast config that breaks SLAs is not optimization — it is a incident.

Your job:
- Analyse profiling data, metrics, query plans, and infrastructure signals provided.
- Identify bottlenecks: network latency, database I/O, service CPU, alert processing throughput.
- Separate quick wins (high payoff, low risk) from structural changes that need planning.
- Flag anything that looks slow but must not change — correctness and contracts outrank speed.
- For NOC: focus on latency percentiles, throughput, capacity headroom, and alert pipeline health.
- If before/after data is provided, evaluate and compute the delta clearly.
- Output a strict JSON report matching the OptimizerOutput schema.

Rules:
- No measurements, no claims. If data is missing, flag it and state what metrics are needed.
- Every bottleneck needs a category (cpu|memory|io|network|database|concurrency), cost, and recommendation.
- `quick_wins` are changes a NOC engineer can apply today without rethinking the architecture.
- `do_not_touch` is not optional. Always populate it for critical paths and production configs.
- Verdict: "fast" = within SLA. "sluggish" = measurable drag. "unacceptable" = escalation required.
- Your summary is one paragraph. Numbers only. No feelings.
- Always output valid JSON matching the OptimizerOutput schema.
""".strip()

    # -----------------------------------------------------------------------
    # Message construction
    # -----------------------------------------------------------------------

    def build_messages(self, context: AgentContext) -> list[dict[str, str]]:
        profiling_data  = context.extra.get("profiling_data", {})
        benchmarks      = context.extra.get("benchmarks", {})
        flame_graph     = context.extra.get("flame_graph_summary", "")
        query_plans     = context.extra.get("query_plans", [])
        baseline        = context.extra.get("baseline_metrics", {})
        after_metrics   = context.extra.get("after_metrics", {})
        do_not_touch    = context.extra.get("do_not_touch_hints", [])
        perf_budget     = context.extra.get("performance_budget", {})
        changed_files   = context.extra.get("changed_files", [])

        user_content = f"""
## NOC Performance Analysis Request

**Task ID**: {context.task_id}
**Objective**: {context.objective}
**Repo**: {context.repo_path}
**Risk Level**: {context.risk_level}

---

### Performance Budget
```json
{json.dumps(perf_budget, indent=2) if perf_budget else "No performance budget defined. Flag this — you cannot judge 'fast' without a target."}
```

### Acceptance Criteria
{chr(10).join(f"- {c}" for c in context.acceptance_criteria) if context.acceptance_criteria else "- None specified."}

### Constraints
{chr(10).join(f"- {c}" for c in context.constraints) if context.constraints else "- None specified."}

### Do Not Touch Hints
```
{chr(10).join(f"- {h}" for h in do_not_touch) if do_not_touch else "None provided. Infer from context and populate conservatively."}
```

### Changed Files
```
{chr(10).join(f"- {f}" for f in changed_files) if changed_files else "No changed files listed. Treat full file_context as scope."}
```

### File Context (source under analysis)
```python
{chr(10).join(f"# {fname}{chr(10)}{snippet}" for fname, snippet in context.file_context.items()) if context.file_context else "No source provided. Analyse profiling data alone and flag the gap."}
```

### Profiling Data
```json
{json.dumps(profiling_data, indent=2) if profiling_data else "No profiling data provided. Flag as a critical gap — diagnoses without profiles are guesses."}
```

### Flame Graph Summary
```
{flame_graph if flame_graph else "No flame graph provided."}
```

### Benchmarks
```json
{json.dumps(benchmarks, indent=2) if benchmarks else "No benchmark data provided."}
```

### Query Plans
```json
{json.dumps(query_plans, indent=2) if query_plans else "No query plans provided."}
```

### Baseline Metrics
```json
{json.dumps(baseline, indent=2) if baseline else "No baseline provided. Results list will be empty."}
```

### After Metrics (post-optimization)
```json
{json.dumps(after_metrics, indent=2) if after_metrics else "No after metrics provided. Results list will be empty."}
```

### Prior Agent Output
```json
{json.dumps(context.previous_output, indent=2) if context.previous_output else "{}"}
```

---

Analyse all signals. Identify bottlenecks. Separate quick wins from structural work.
Return a JSON object that strictly matches the OptimizerOutput schema.
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

        try:
            data = json.loads(json_str)
            output = OptimizerOutput(**data)
        except Exception as exc:
            # Bruno would clock a parse failure as latency he didn't budget for
            return {
                "agent": "optimizer",
                "persona": "Benchmark Bruno",
                "verdict": "error",
                "parse_error": str(exc),
                "raw_response": raw,
            }

        return {
            "agent": "optimizer",
            "persona": "Benchmark Bruno",
            **output.model_dump(),
        }
