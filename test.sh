#!/usr/bin/env bash

# Activate virtual environment
source .venv/bin/activate


ruff check .
mypy src
bandit -r src -f txt -o bandit.txt
semgrep ci --config p/owasp-top-ten --config p/python --timeout 120 --error || true
gitleaks detect -v --report-format sarif --report-path gitleaks.sarif || true
