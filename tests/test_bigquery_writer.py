import sys
import os
from unittest.mock import patch, MagicMock

# Stub GCP libraries before importing app modules so tests need no credentials
sys.modules.setdefault("google", MagicMock())
sys.modules.setdefault("google.cloud", MagicMock())
sys.modules.setdefault("google.cloud.asset_v1", MagicMock())
sys.modules.setdefault("google.cloud.bigquery", MagicMock())

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../app"))

from bigquery_writer import write_findings_to_bigquery  # noqa: E402

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


class TestWriteFindingsToBigqueryEmpty:
    def test_empty_findings_returns_empty_list(self):
        errors = write_findings_to_bigquery("test-project", [])
        assert errors == []

    @patch("bigquery_writer.bigquery.Client")
    def test_empty_findings_does_not_call_bigquery(self, mock_client_cls):
        write_findings_to_bigquery("test-project", [])
        mock_client_cls.assert_not_called()


class TestWriteFindingsToBigquerySuccess:
    @patch("bigquery_writer.bigquery.Client")
    def test_success_returns_empty_errors(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.insert_rows_json.return_value = []

        errors = write_findings_to_bigquery("test-project", [SAMPLE_FINDING])

        assert errors == []

    @patch("bigquery_writer.bigquery.Client")
    def test_client_created_with_correct_project(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.insert_rows_json.return_value = []

        write_findings_to_bigquery("my-project", [SAMPLE_FINDING])

        mock_client_cls.assert_called_once_with(project="my-project")

    @patch("bigquery_writer.bigquery.Client")
    def test_insert_rows_called_with_correct_table(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.insert_rows_json.return_value = []

        write_findings_to_bigquery("my-project", [SAMPLE_FINDING])

        call_args = mock_client.insert_rows_json.call_args
        table_ref = call_args[0][0]
        assert table_ref == "my-project.cloudguard.findings"

    @patch("bigquery_writer.bigquery.Client")
    def test_all_findings_passed_to_insert(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.insert_rows_json.return_value = []

        findings = [SAMPLE_FINDING, {**SAMPLE_FINDING, "check_id": "CG-002"}]
        write_findings_to_bigquery("test-project", findings)

        call_args = mock_client.insert_rows_json.call_args
        inserted = call_args[0][1]
        assert len(inserted) == 2


class TestWriteFindingsToBigqueryErrors:
    @patch("bigquery_writer.bigquery.Client")
    def test_bigquery_errors_returned(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        bq_errors = [{"index": 0, "errors": [{"reason": "invalid"}]}]
        mock_client.insert_rows_json.return_value = bq_errors

        errors = write_findings_to_bigquery("test-project", [SAMPLE_FINDING])

        assert errors == bq_errors

    @patch("bigquery_writer.bigquery.Client")
    def test_multiple_errors_all_returned(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        bq_errors = [
            {"index": 0, "errors": [{"reason": "invalid"}]},
            {"index": 1, "errors": [{"reason": "quota_exceeded"}]},
        ]
        mock_client.insert_rows_json.return_value = bq_errors

        findings = [SAMPLE_FINDING, {**SAMPLE_FINDING, "check_id": "CG-002"}]
        errors = write_findings_to_bigquery("test-project", findings)

        assert len(errors) == 2
