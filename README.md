# cloudguard-gcp-governance
A GCP governance platform that scans cloud resources for security, cost, and compliance risks using Cloud Run, Cloud Asset Inventory, BigQuery, and Looker Studio.

# CloudGuard – GCP Governance & Risk Visibility Platform

## Project Question
How can organisations automatically detect cloud misconfigurations, identify cost waste, and produce actionable governance insights before those issues become security, operational, or financial problems?

## Overview
CloudGuard is a serverless governance platform built on Google Cloud. It scans cloud resources using Cloud Asset Inventory, applies lightweight governance checks, stores findings in BigQuery, and visualises issues in Looker Studio.

## Version 1 Scope
This project checks for:
- Public IP exposure on VM instances
- Overly permissive firewall rules
- Missing required labels
- Unattached persistent disks
- Severity classification of findings
