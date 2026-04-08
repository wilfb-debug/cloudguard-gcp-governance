# Contributing to CloudGuard

CloudGuard is a GCP governance scanner. Contributions that add new rules, improve existing checks, or extend the BigQuery schema are welcome.

---

## Local Setup

**Prerequisites:** Python 3.11+, Docker (optional)

```bash
git clone https://github.com/wilfb-debug/cloudguard-gcp-governance.git
cd cloudguard-gcp-governance

# Install app dependencies
pip install -r app/requirements.txt

# Install dev/test dependencies
pip install -r requirements-dev.txt
```

---

## Running Tests

Tests require no GCP credentials — all cloud libraries are stubbed.

```bash
# Run all tests
python -m pytest tests/ -v

# Run with coverage report
python -m pytest tests/ --cov=app --cov-report=term-missing

# Run a single test file
python -m pytest tests/test_rules.py -v
```

---

## Running Locally

```bash
export GOOGLE_CLOUD_PROJECT=your-project-id

cd app
python main.py
# → http://localhost:8080
# → http://localhost:8080/scan  (requires GCP credentials)
```

---

## Adding a New Rule

Rules live in `app/rules.py`. Each rule is a standalone function that takes an asset and returns a list of findings (empty if no issue found).

**Step 1 — Write the rule function:**

```python
def check_my_new_rule(asset, resource_data, project_id, scan_timestamp):
    findings = []

    if asset.asset_type != "compute.googleapis.com/SomeType":
        return findings

    # your detection logic here

    if some_condition:
        findings.append(
            build_finding(
                project_id=project_id,
                scan_timestamp=scan_timestamp,
                resource_name=asset.name,
                resource_type=asset.asset_type,
                resource_location=resource_data.get("zone", "unknown"),
                check_id="CG-005",          # next available ID
                finding_title="Short description of the issue",
                category="Security",        # Security | Cost | Governance
                severity="High",            # High | Medium | Low
                recommendation="What the user should do to fix it."
            )
        )

    return findings
```

**Step 2 — Register the rule in `app/scanner.py`:**

```python
from rules import (
    ...
    check_my_new_rule,   # add this
)

# Inside run_scan(), add:
findings.extend(
    check_my_new_rule(asset, resource_data, PROJECT_ID, scan_timestamp)
)
```

**Step 3 — Add tests in `tests/test_rules.py`:**

Every rule needs at minimum:
- A test for the wrong asset type (should return `[]`)
- A test for the condition being triggered (should return 1 finding with the correct `check_id`)
- A test for the condition NOT being triggered (should return `[]`)

---

## Code Style

- Max line length: **100 characters** (enforced by flake8)
- Use type hints where practical
- Rule functions must always return a list (never `None`)
- Check IDs follow the pattern `CG-NNN` (next available number)

```bash
# Run linter before opening a PR
flake8 app/ --max-line-length=100 --exclude=app/venv
```

---

## CI

Every pull request runs:
1. **flake8** — linting
2. **pytest** — 28+ unit tests with 80% coverage gate
3. **docker build** — confirms the image builds cleanly

PRs that fail CI will not be merged.
