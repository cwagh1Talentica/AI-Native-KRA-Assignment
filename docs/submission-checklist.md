# Submission Checklist (Target: 100/100)

Use this checklist before final submission.

## Phase 1 (30 pts)
- [ ] Run `main.py --phase 1` and verify `deliverables/phase1/vampi_api_catalog.json` exists.
- [ ] Confirm required endpoints are present in catalog:
  - `GET /users/v1`
  - `POST /users/v1/register`
  - `POST /users/v1/login`
  - `GET /users/v1/{user_id}`
  - `DELETE /users/v1/{user_id}`
  - `PUT /users/v1/{user_id}/email`
  - `PUT /users/v1/{user_id}/password`
  - `GET /books/v1`
  - `POST /books/v1`
  - `GET /books/v1/{book_title}`
- [ ] Ensure metadata includes methods, parameters, and auth indicators.

## Phase 2 (35 pts)
- [ ] Run `main.py --phase 2` and verify `deliverables/phase2/vampi_vulnerability_assessment.json` exists.
- [ ] Confirm findings include known VAmPI vulnerability areas (API1, API2, API3, API6, API8, API9 at minimum when observable).
- [ ] Confirm each finding includes severity, CVSS score, PoC, remediation, and evidence.

## Phase 3 (35 pts)
- [ ] Run `main.py --phase 3` and verify:
  - `deliverables/phase3/integrated_security_assessment.json`
  - `reports/vampi-security-assessment.json`
  - `reports/vampi-security-assessment.html`
- [ ] Confirm sequential agent workflow is visible in code (`orchestrator/pipeline.py`).
- [ ] Confirm CrewAI objects are used (`Agent`, `Task`, `Crew`, `Process`).

## Demo Readiness
- [ ] Record 8-minute demo:
  1. Start VAmPI via Docker
  2. Run phase 1/2/3 commands
  3. Show discovered endpoints
  4. Show vulnerability findings and PoCs
  5. Show HTML/JSON reports
  6. Briefly explain remediation priorities

## Final Quality Gate
- [ ] Run tests: `.venv/bin/python -m pytest -q`
- [ ] Ensure no credentials/secrets are committed
- [ ] Ensure docs are present: `README.md`, `docs/phase1.md`, `docs/phase2.md`, `docs/phase3.md`
