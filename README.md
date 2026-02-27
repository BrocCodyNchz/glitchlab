# **⚡ GLITCHLAB** v2.2.0

**The Agentic SOC/NOC Engine — Build Weird. Ship Clean.**  
A local, repo-agnostic, multi-agent engine for Security Operations Center (SOC) and Network Operations Center (NOC) workflows. Evolves runbooks, playbooks, and configs under strict governance.

---

## **What It Does**

GLITCHLAB takes a security incident, alert, or NOC ticket (GitHub issue, local YAML, or interactive prompt), breaks it into a response plan, implements runbook changes, validates execution, fixes failures, scans for security issues, and opens a PR—all orchestrated locally with deterministic control.

---

## **Agent Roster**

| Agent | Role | Model | Energy |
| ----- | ----- | ----- | ----- |
| 🧠 **Professor Zap** | Planner | Gemini | SOC/NOC incident planner — war room whiteboard chaos |
| 🔧 **Patch** | Implementer | Gemini | Response executor — playbooks, configs, firewall rules |
| 🐛 **Reroute** | Debugger | Gemini | Incident triage — fixes failed runbook steps |
| 🔒 **Firewall Frankie** | Security | Gemini | SOC threat analyst — magnifying glass + threat intel |
| 📦 **Semver Sam** | Release | Gemini | Change manager — change control, changelog |
| 📚 **Archivist Nova** | Archivist | Gemini | Documenter — incident post-mortems, runbook docs |
| ⚡ **Benchmark Bruno** | Optimizer | Gemini | NOC performance analyst — latency, throughput, capacity |
| 💀 **Zero-Day Ella** | Red Team | Gemini | SOC penetration tester — she just gets in. |

---

## **Quick Start**

### **1\. Install**

`cd glitchlab`  
`pip install -e .`

### **2\. Configure API Keys**

`cp .env.example .env`  
`# Edit .env with your keys:`  
`# ANTHROPIC_API_KEY=sk-ant-...`  
`# GOOGLE_API_KEY=AI...`

### **3\. Initialize a Repository**

`cd ~/your-project`  
`glitchlab init  # Bootstraps .glitchlab (defaults to current directory)`

### **4\. Run**

From a GitHub issue:

`glitchlab run --repo . --issue 42`

From a local task file:

`glitchlab run --repo . --local-task`

Interactive mode:

`glitchlab interactive --repo .`

### **5\. Check Status**

`glitchlab status --repo .`

---

## **Task Sources**

* **GitHub Issues:** Label issues with `glitchlab` for incident/alert tickets. Use the provided issue template.

* **Local YAML Tasks:** Create files under `.glitchlab/tasks/queue/next.yaml` for runbook changes or NOC tickets.

* **Interactive:** Describe the incident, alert, or change. GLITCHLAB plans, you approve, it executes.

---

## **Human Intervention Points**

GLITCHLAB is autonomous between checkpoints, but you stay in control:

* **Plan Review:** Approve before implementation begins.

* **Core Boundary:** Use `--allow-core` for protected paths.

* **Fix Loop:** Halts after a set number of failed attempts and asks what to do next.

* **Pre-PR Review:** View the diff and approve or cancel before the PR opens.

* **Budget Cap:** Halts if a token/dollar limit is exceeded.

---

## **Architecture**

The **Controller** is the brainstem. It never writes code directly; it only coordinates.

### **Project Structure (v2.2.0)**

`glitchlab/`  
`├── cli.py              # CLI interface (typer)`  
`├── controller.py       # The brainstem`  
`├── router.py           # Vendor-agnostic model routing`  
`├── config_loader.py    # Config loading + merging`  
`├── identity.py         # Versioning and branding`  
`├── agents/             # The roster (Zap, Patch, Reroute, etc.)`  
`├── workspace/          # Git worktree isolation & tools`  
`├── governance/         # Boundary enforcement`  
`└── templates/          # Task and config templates`

---

## **Design Principles**

* **Local-first:** Runs on your machine.

* **Repo-agnostic:** Works with Rust, Python, TypeScript, Go—anything.

* **Deterministic:** Controller logic is explicit, not probabilistic.

* **Bounded:** Budget caps, retry limits, and tool allowlists keep operations contained.

* **Under 2k lines:** Maintainable, focused, and fast.

---

## **License**

MIT — Adjective LLC
