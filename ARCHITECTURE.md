# CloudGuard Architecture

## Overview

CloudGuard is a serverless GCP governance platform deployed on Cloud Run. It scans live cloud resources using the Cloud Asset Inventory API, evaluates them against a set of security, cost, and governance rules, and writes structured findings to BigQuery for dashboarding and alerting.

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        GCP Project                          │
│                                                             │
│  ┌──────────────┐    ┌──────────────────────────────────┐  │
│  │   Scheduler  │───▶│        Cloud Run (CloudGuard)    │  │
│  │  (optional)  │    │                                  │  │
│  └──────────────┘    │  GET /scan                       │  │
│                      │  GET /findings?severity=High     │  │
│  ┌──────────────┐    │  GET /health                     │  │
│  │   IAP / IAM  │───▶│                                  │  │
│  │  (auth gate) │    └──────────┬───────────────────────┘  │
│  └──────────────┘               │                          │
│                         ┌───────▼────────┐                 │
│                         │  Cloud Asset   │                 │
│                         │  Inventory API │                 │
│                         └───────┬────────┘                 │
│                                 │ assets                   │
│                         ┌───────▼────────┐                 │
│                         │  Rules Engine  │                 │
│                         │  (rules.py)    │                 │
│                         └───────┬────────┘                 │
│                                 │ findings                 │
│                         ┌───────▼────────┐                 │
│                         │   BigQuery     │                 │
│                         │ cloudguard.    │                 │
│                         │   findings     │                 │
│                         └───────┬────────┘                 │
│                                 │                          │
│                         ┌───────▼────────┐                 │
│                         │ Looker Studio  │                 │
│                         │  Dashboard     │                 │
│                         └────────────────┘                 │
└─────────────────────────────────────────────────────────────┘
```

---

## Request Flow

```
Client Request
     │
     ▼
GET /findings?severity=High&category=Security
     │
     ▼
┌────────────────────────┐
│  Input Validation      │  ← validates severity, category, limit, offset
└────────┬───────────────┘
         │
         ▼
┌────────────────────────┐
│  scanner.run_scan()    │  ← calls Cloud Asset Inventory API
│                        │    iterates: Instances, Firewalls, Disks
└────────┬───────────────┘
         │  raw assets
         ▼
┌────────────────────────┐
│  Rules Engine          │
│  ├── CG-001: Public IP │
│  ├── CG-002: Open FW   │
│  ├── CG-003: Labels    │
│  └── CG-004: Idle Disk │
└────────┬───────────────┘
         │  findings[]
         ▼
┌────────────────────────┐
│  Filter + Paginate     │  ← applies severity/category/check_id filters
│                        │    applies limit/offset
└────────┬───────────────┘
         │
         ▼
   JSON Response
   {total, limit, offset, findings[]}
```

---

## Module Responsibilities

| Module | Responsibility |
|---|---|
| `main.py` | Flask app, route definitions, input validation, response shaping |
| `scanner.py` | Calls Cloud Asset Inventory API, returns raw asset list |
| `rules.py` | Stateless rule functions — each takes an asset, returns findings |
| `bigquery_writer.py` | Writes findings to BigQuery `cloudguard.findings` table |

---

## BigQuery Schema

**Dataset:** `cloudguard`
**Table:** `findings`

| Field | Type | Description |
|---|---|---|
| `scan_timestamp` | STRING | ISO 8601 UTC timestamp of the scan |
| `project_id` | STRING | GCP project ID scanned |
| `resource_name` | STRING | Full GCP resource name |
| `resource_type` | STRING | Asset type (e.g. `compute.googleapis.com/Instance`) |
| `resource_location` | STRING | Zone, region, or `global` |
| `check_id` | STRING | Rule identifier (e.g. `CG-001`) |
| `finding_title` | STRING | Human-readable issue summary |
| `category` | STRING | `Security`, `Cost`, or `Governance` |
| `severity` | STRING | `High`, `Medium`, or `Low` |
| `status` | STRING | `open` (default) |
| `recommendation` | STRING | Actionable remediation guidance |

---

## API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Service info and available endpoints |
| `/health` | GET | Health check with version |
| `/scan` | GET | Run full scan, write findings to BigQuery |
| `/findings` | GET | Run scan, return filtered and paginated findings |

**`/findings` query parameters:**

| Parameter | Values | Default |
|---|---|---|
| `severity` | `High`, `Medium`, `Low` | all |
| `category` | `Security`, `Cost`, `Governance` | all |
| `check_id` | `CG-001` … `CG-004` | all |
| `limit` | 1–200 | 50 |
| `offset` | ≥0 | 0 |

---

## Rule Catalogue

| Check ID | Title | Category | Severity |
|---|---|---|---|
| CG-001 | VM has public IP | Security | High |
| CG-002 | Firewall allows 0.0.0.0/0 ingress | Security | High |
| CG-003 | Missing required labels (env, owner) | Governance | Medium |
| CG-004 | Unattached persistent disk | Cost | Medium |

---

## Infrastructure

Deployed via Terraform in the `/terraform` directory:

```
terraform/
├── main.tf          # Cloud Run service, Artifact Registry
├── iam.tf           # Service account, IAM bindings
├── variables.tf     # Input variables
└── outputs.tf       # Service URL output
```

IAM bindings granted to the Cloud Run service account:
- `roles/cloudasset.viewer` — read Cloud Asset Inventory
- `roles/bigquery.dataEditor` — write findings to BigQuery
