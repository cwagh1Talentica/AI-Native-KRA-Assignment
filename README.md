# API Security Testing Duo (VAmPI)

Two-agent API security testing system for VAmPI using CrewAI orchestration.

## Project Phases and Deliverables

This repository is structured to match the assignment's 3-phase timeline:

1. **Phase 1 (Discovery Agent):**
   - Agent: `discovery_agent/agent.py`
   - Deliverable artifact: `deliverables/phase1/vampi_api_catalog.json`
   - Documentation: `docs/phase1.md`

2. **Phase 2 (Security Testing Agent):**
   - Agent: `security_agent/agent.py`
   - Deliverable artifact: `deliverables/phase2/vampi_vulnerability_assessment.json`
   - Documentation: `docs/phase2.md`

3. **Phase 3 (Integrated Platform):**
   - Orchestration: `orchestrator/pipeline.py` (CrewAI agents + sequential crew)
   - Reports: `reports/vampi-security-assessment.json`, `reports/vampi-security-assessment.html`
   - Integrated deliverable: `deliverables/phase3/integrated_security_assessment.json`
   - Documentation: `docs/phase3.md`
   - Submission checklist: `docs/submission-checklist.md`
   - Live demo script: `docs/live-demo-script.md`

## Run Commands

Start VAmPI:

```bash
docker run -p 5000:5000 erev0s/vampi
```

Run each phase:

```bash
# Phase 1
.venv/bin/python main.py --phase 1 --base-url http://localhost:5000

# Phase 2
.venv/bin/python main.py --phase 2 --base-url http://localhost:5000

# Phase 3 (full integrated workflow)
.venv/bin/python main.py --phase 3 --base-url http://localhost:5000
```

Run tests:

```bash
.venv/bin/python -m pytest -q
```

Run complete demo flow:

```bash
./run_live_demo.sh
```

Continuous monitoring mode:

```bash
.venv/bin/python continuous_monitor.py --base-url http://localhost:5000 --interval-seconds 300 --iterations 3
```

Configuration is externalized in JSON under `config/data/`:
- `discovery_catalog.json` (fallback endpoint catalog)
- `security_payloads.json` (payloads, probe IDs, mass-assignment keys)
- `security_policies.json` (JWT/password/rate-limit/policy thresholds)
- `compliance_mapping.json` (OWASP ↔ NIST/ISO mapping, including 2019 labels)
