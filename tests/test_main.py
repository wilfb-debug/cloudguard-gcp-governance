import sys
import os
from unittest.mock import patch, MagicMock

# Stub GCP libraries before importing app modules so tests need no credentials
sys.modules.setdefault("google", MagicMock())
sys.modules.setdefault("google.cloud", MagicMock())
sys.modules.setdefault("google.cloud.asset_v1", MagicMock())
sys.modules.setdefault("google.cloud.bigquery", MagicMock())

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../app"))

import pytest
from main import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


SAMPLE_FINDING = {
    "scan_timestamp": "2026-01-01T00:00:00+00:00",
    "project_id": "test-project",
    "resource_name": "//compute/instance/my-vm",
    "resource_type": "compute.googleapis.com/Instance",
    "resource_location": "us-central1-a",
    "check_id": "CG-001",
    "finding_title": "VM has public IP",
    "category": "Security",
    "severity": "High",
    "status": "open",
    "recommendation": "Remove external IP.",
}


class TestHomeEndpoint:
    def test_returns_200(self, client):
        response = client.get("/")
        assert response.status_code == 200

    def test_returns_running_message(self, client):
        response = client.get("/")
        data = response.get_json()
        assert "message" in data
        assert "CloudGuard" in data["message"]


class TestHealthEndpoint:
    def test_returns_200(self, client):
        response = client.get("/health")
        assert response.status_code == 200

    def test_returns_status_ok(self, client):
        response = client.get("/health")
        data = response.get_json()
        assert data["status"] == "ok"

    def test_returns_version(self, client):
        response = client.get("/health")
        data = response.get_json()
        assert "version" in data
        assert data["version"] != ""


class TestScanEndpoint:
    @patch("main.write_findings_to_bigquery", return_value=[])
    @patch("main.run_scan", return_value=[SAMPLE_FINDING])
    def test_returns_200_with_findings(self, mock_scan, mock_write, client):
        response = client.get("/scan")
        assert response.status_code == 200

    @patch("main.write_findings_to_bigquery", return_value=[])
    @patch("main.run_scan", return_value=[SAMPLE_FINDING])
    def test_finding_count_matches(self, mock_scan, mock_write, client):
        response = client.get("/scan")
        data = response.get_json()
        assert data["finding_count"] == 1
        assert len(data["findings"]) == 1

    @patch("main.write_findings_to_bigquery", return_value=[])
    @patch("main.run_scan", return_value=[])
    def test_empty_scan_returns_zero_count(self, mock_scan, mock_write, client):
        response = client.get("/scan")
        data = response.get_json()
        assert data["finding_count"] == 0
        assert data["findings"] == []

    @patch("main.write_findings_to_bigquery", return_value=[{"error": "insert failed"}])
    @patch("main.run_scan", return_value=[SAMPLE_FINDING])
    def test_bigquery_errors_included_in_response(self, mock_scan, mock_write, client):
        response = client.get("/scan")
        assert response.status_code == 200
        data = response.get_json()
        assert len(data["bigquery_errors"]) == 1

    @patch("main.write_findings_to_bigquery", return_value=[])
    @patch("main.run_scan", return_value=[SAMPLE_FINDING, SAMPLE_FINDING])
    def test_multiple_findings_correct_count(self, mock_scan, mock_write, client):
        response = client.get("/scan")
        data = response.get_json()
        assert data["finding_count"] == 2
