# Phase 2 - Security Testing Specialist Agent

## Goal
Test discovered endpoints for OWASP API Top 10 vulnerabilities.

## Implementation
- Security agent: `security_agent/agent.py`
- Key checks include:
  - API1 Broken Object Level Authorization
  - API2 Broken Authentication (JWT and password policy checks)
  - API3 Excessive Data Exposure
  - API4 Unrestricted Resource Consumption (rate limiting)
  - API5 Broken Function Level Authorization
  - API6 Mass Assignment
  - API7 Security Misconfiguration
  - API8 Injection
  - API9 Improper Inventory Management
  - API10 Unsafe Consumption of APIs
- CVSS-like scores, severity, PoC, and remediation are produced per finding.

## Endpoint-Level Coverage
Direct tests include:
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

## Deliverables
- Security assessment artifact: `deliverables/phase2/vampi_vulnerability_assessment.json`
- Source code: security testing module + tests

## Success Criteria Mapping
- Detects known vulnerabilities: covered
- PoC details: covered in each finding
- CVSS scoring: covered via `cvss_score`
- Professional report shape: covered in JSON + HTML downstream
