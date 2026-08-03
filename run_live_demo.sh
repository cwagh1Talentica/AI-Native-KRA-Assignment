#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "== Phase 1: Discovery =="
.venv/bin/python main.py --phase 1 --base-url http://localhost:5000

echo
echo "== Phase 2: Security Testing =="
.venv/bin/python main.py --phase 2 --base-url http://localhost:5000

echo
echo "== Phase 3: Integrated Assessment =="
.venv/bin/python main.py --phase 3 --base-url http://localhost:5000

echo
echo "Artifacts:"
echo "  - deliverables/phase1/vampi_api_catalog.json"
echo "  - deliverables/phase2/vampi_vulnerability_assessment.json"
echo "  - deliverables/phase3/integrated_security_assessment.json"
echo "  - reports/vampi-security-assessment.json"
echo "  - reports/vampi-security-assessment.html"
