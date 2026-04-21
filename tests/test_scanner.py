import sys
import os
from unittest.mock import patch, MagicMock

# Stub GCP libraries before importing app modules so tests need no credentials
sys.modules.setdefault("google", MagicMock())
sys.modules.setdefault("google.cloud", MagicMock())
sys.modules.setdefault("google.cloud.asset_v1", MagicMock())
sys.modules.setdefault("google.cloud.bigquery", MagicMock())

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../app"))

from scanner import run_scan  # noqa: E402


def _make_mock_asset(asset_type: str, resource_data: dict) -> MagicMock:
    asset = MagicMock()
    asset.asset_type = asset_type
    asset.name = f"//compute.googleapis.com/projects/test/{asset_type}/{asset_type}-1"
    asset.resource.data = resource_data
    return asset


class TestRunScanEmpty:
    @patch("scanner.asset_v1.AssetServiceClient")
    def test_no_assets_returns_empty(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.list_assets.return_value = []

        findings = run_scan()

        assert findings == []
        mock_client.list_assets.assert_called_once()


class TestRunScanVmPublicIp:
    @patch("scanner.asset_v1.AssetServiceClient")
    def test_vm_with_public_ip_produces_cg001(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.list_assets.return_value = [
            _make_mock_asset("compute.googleapis.com/Instance", {
                "networkInterfaces": [{"accessConfigs": [{"natIP": "34.1.2.3"}]}],
                "zone": "zones/us-central1-a",
            })
        ]

        findings = run_scan()

        check_ids = [f["check_id"] for f in findings]
        assert "CG-001" in check_ids

    @patch("scanner.asset_v1.AssetServiceClient")
    def test_vm_without_public_ip_produces_no_cg001(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.list_assets.return_value = [
            _make_mock_asset("compute.googleapis.com/Instance", {
                "networkInterfaces": [{"accessConfigs": []}],
                "zone": "zones/us-central1-a",
                "labels": {"env": "prod", "owner": "team"},
            })
        ]

        findings = run_scan()

        assert not any(f["check_id"] == "CG-001" for f in findings)


class TestRunScanFirewall:
    @patch("scanner.asset_v1.AssetServiceClient")
    def test_open_ingress_firewall_produces_cg002(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.list_assets.return_value = [
            _make_mock_asset("compute.googleapis.com/Firewall", {
                "direction": "INGRESS",
                "sourceRanges": ["0.0.0.0/0"],
                "labels": {"env": "prod", "owner": "team"},
            })
        ]

        findings = run_scan()

        check_ids = [f["check_id"] for f in findings]
        assert "CG-002" in check_ids


class TestRunScanDisk:
    @patch("scanner.asset_v1.AssetServiceClient")
    def test_unattached_disk_produces_cg004(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.list_assets.return_value = [
            _make_mock_asset("compute.googleapis.com/Disk", {
                "zone": "zones/us-central1-a",
            })
        ]

        findings = run_scan()

        check_ids = [f["check_id"] for f in findings]
        assert "CG-004" in check_ids

    @patch("scanner.asset_v1.AssetServiceClient")
    def test_attached_disk_no_cg004(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.list_assets.return_value = [
            _make_mock_asset("compute.googleapis.com/Disk", {
                "zone": "zones/us-central1-a",
                "users": ["projects/test/instances/my-vm"],
                "labels": {"env": "prod", "owner": "team"},
            })
        ]

        findings = run_scan()

        assert not any(f["check_id"] == "CG-004" for f in findings)


class TestRunScanMultipleAssets:
    @patch("scanner.asset_v1.AssetServiceClient")
    def test_multiple_assets_all_findings_collected(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.list_assets.return_value = [
            _make_mock_asset("compute.googleapis.com/Instance", {
                "networkInterfaces": [{"accessConfigs": [{"natIP": "34.1.2.3"}]}],
                "zone": "zones/us-central1-a",
            }),
            _make_mock_asset("compute.googleapis.com/Firewall", {
                "direction": "INGRESS",
                "sourceRanges": ["0.0.0.0/0"],
            }),
            _make_mock_asset("compute.googleapis.com/Disk", {
                "zone": "zones/us-central1-a",
            }),
        ]

        findings = run_scan()

        check_ids = {f["check_id"] for f in findings}
        assert "CG-001" in check_ids
        assert "CG-002" in check_ids
        assert "CG-003" in check_ids
        assert "CG-004" in check_ids

    @patch("scanner.asset_v1.AssetServiceClient")
    def test_finding_has_required_fields(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.list_assets.return_value = [
            _make_mock_asset("compute.googleapis.com/Disk", {
                "zone": "zones/us-central1-a",
            })
        ]

        findings = run_scan()

        assert len(findings) >= 1
        finding = findings[0]
        for field in ("check_id", "severity", "category", "status", "project_id",
                      "scan_timestamp", "resource_name", "resource_type"):
            assert field in finding, f"Missing field: {field}"
