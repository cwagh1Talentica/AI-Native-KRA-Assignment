# Live Demo Script (8 Minutes)

Use this script for your final evaluation demo.

## 0. Demo Goal (0:00 - 0:30)
Say:
- "This is a two-agent API security testing system for VAmPI."
- "Agent 1 discovers endpoints; Agent 2 tests OWASP API Top 10 vulnerabilities."
- "I will show phase-wise outputs and final integrated reporting."

## 1. Start Target (0:30 - 1:00)
Run:
```bash
docker run -p 5000:5000 erev0s/vampi
```
Say:
- "Testing is local-only on authorized VAmPI container."

## 2. Phase 1 - Discovery (1:00 - 2:30)
Run:
```bash
cd /Users/cwagh/api-security-duo
.venv/bin/python main.py --phase 1 --base-url http://localhost:5000
```
Show:
- `deliverables/phase1/vampi_api_catalog.json`
- Confirm required endpoints exist (users/books set from assignment).
Say:
- "Discovery includes endpoint metadata, auth hints, categorization, and risk tags."

## 3. Phase 2 - Security Testing (2:30 - 4:30)
Run:
```bash
.venv/bin/python main.py --phase 2 --base-url http://localhost:5000
```
Show:
- `deliverables/phase2/vampi_vulnerability_assessment.json`
- At least these finding types:
  - API1 BOLA
  - API2 Authentication/JWT/password policy
  - API3 Data exposure
  - API6 Mass assignment
  - API8 Injection
  - API9 Asset management
Say:
- "Each finding includes evidence, PoC, CVSS score, and remediation."

## 4. Phase 3 - Integration + Professional Report (4:30 - 6:30)
Run:
```bash
.venv/bin/python main.py --phase 3 --base-url http://localhost:5000
```
Show:
- `deliverables/phase3/integrated_security_assessment.json`
- `reports/vampi-security-assessment.json`
- `reports/vampi-security-assessment.html` (open in browser)
Say:
- "This is the integrated sequential workflow: Discovery -> Security Testing -> Reporting."
- "The orchestrator uses CrewAI agents and tasks."

## 5. Code Evidence (6:30 - 7:30)
Show:
- `orchestrator/pipeline.py` (CrewAI Agent/Task/Crew wiring)
- `discovery_agent/agent.py`
- `security_agent/agent.py`
- `docs/phase1.md`, `docs/phase2.md`, `docs/phase3.md`
Say:
- "Phase deliverables are explicit and reviewer-friendly in this repo."

## 6. Closing (7:30 - 8:00)
Say:
- "This system covers OWASP API Top 10 checks, produces actionable security findings, and demonstrates coordinated two-agent security automation."
