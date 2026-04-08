# CloudGuard – GCP Governance & Risk Visibility Platform

[![CI](https://github.com/wilfb-debug/cloudguard-gcp-governance/actions/workflows/ci.yml/badge.svg)](https://github.com/wilfb-debug/cloudguard-gcp-governance/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![GCP](https://img.shields.io/badge/GCP-Cloud_Run-4285F4?logo=googlecloud&logoColor=white)
![Tests](https://img.shields.io/badge/tests-41_passing-brightgreen)
![Coverage](https://img.shields.io/badge/coverage-80%25+-brightgreen)

**🚀 Live Demo:** https://cloudguard-922790829947.europe-west2.run.app

> Serverless GCP governance platform — scans cloud resources for security misconfigurations, cost waste, and compliance violations. Findings written to BigQuery and queryable via REST API with filtering and pagination.

## Project Question

How can organisations automatically detect cloud misconfigurations, identify cost waste, and produce actionable governance insights before those issues become security, operational, or financial problems?

## Overview

CloudGuard is a serverless governance platform built on Google Cloud. It scans cloud resources using Cloud Asset Inventory, applies lightweight governance checks, stores findings in BigQuery, and visualises issues in Looker Studio.

## Architecture

![CloudGuard Architecture](docs/images/cloudguard-architecture-diagram.png)

## Key Results (Live Evidence)

### Cloud Run Scan Output
![Cloud Run Scan Results](docs/evidence/cloud-run-scan-results.png)

### BigQuery Findings Stored
![BigQuery Findings](docs/evidence/bigquery-findings-ingested.png)

### Cloud Run Service Running
![Cloud Run Home](docs/evidence/cloud-run-home-working.png)

### Scheduler Triggered Scan
![Scheduler Triggered Scan](docs/evidence/scheduler-triggered-scan.png)

## Version 1 Scope

This project checks for:

- Public IP exposure on VM instances
- Overly permissive firewall rules
- Missing required labels
- Unattached persistent disks
- Severity classification of findings

## How It Works

1. Cloud Scheduler triggers a daily scan  
2. Cloud Run exposes a `/scan` API endpoint  
3. Cloud Asset Inventory retrieves all project resources  
4. A custom rule engine evaluates governance and security checks  
5. Findings are written to BigQuery  
6. Data is available for reporting in Looker Studio  

## Local Development (Proof)

![Local Service Running](docs/evidence/local-cloudguard-service-running.png)

![Local Scan Success](docs/evidence/local-scan-success.png)

## Tech Stack

- Google Cloud Platform (GCP)
  - Cloud Run
  - Cloud Scheduler
  - Cloud Asset Inventory
  - BigQuery
- Python
- Flask

## IAM & Security

The Cloud Run service uses least-privilege access:

- Cloud Asset Viewer
- BigQuery Data Editor
- BigQuery Job User

## Project Structure

```
cloudguard-gcp-governance/
│
├── app/
│   ├── main.py
│   ├── scanner.py
│   └── rules.py
│
├── docs/
│   ├── images/
│   │   └── cloudguard-architecture-diagram.png
│   │
│   └── evidence/
│       ├── cloud-run-home-working.png
│       ├── cloud-run-scan-results.png
│       ├── bigquery-findings-ingested.png
│       ├── scheduler-triggered-scan.png
│       ├── local-cloudguard-service-running.png
│       └── local-scan-success.png
│
├── requirements.txt
└── README.md
```

## Running Locally

pip install -r requirements.txt  
export GOOGLE_CLOUD_PROJECT=your-project-id  
gcloud auth application-default login  
python app/main.py  

Open:  
http://127.0.0.1:8080/scan  

## Future Improvements

- Add IAM and storage policy checks
- Add alerting (Slack / email)
- Build a full Looker Studio dashboard
- Support multi-project scanning
- Introduce policy-as-code

## Key Takeaways

- Built a serverless governance platform on GCP
- Automated infrastructure scanning using Cloud Asset Inventory
- Implemented policy-based rule evaluation
- Designed a data pipeline using BigQuery
- Applied IAM best practices for secure service access


