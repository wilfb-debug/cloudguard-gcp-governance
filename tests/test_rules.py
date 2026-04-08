import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../app"))

from rules import (
    build_finding,
    check_vm_public_ip,
    check_firewall_open_ingress,
    check_missing_labels,
    check_unattached_disk,
)
from conftest import make_asset, PROJECT_ID, SCAN_TIMESTAMP


# ---------------------------------------------------------------------------
# build_finding
# ---------------------------------------------------------------------------

class TestBuildFinding:
    def test_returns_all_required_fields(self):
        finding = build_finding(
            project_id=PROJECT_ID,
            scan_timestamp=SCAN_TIMESTAMP,
            resource_name="//compute/instance/my-vm",
            resource_type="compute.googleapis.com/Instance",
            resource_location="us-central1-a",
            check_id="CG-001",
            finding_title="VM has public IP",
            category="Security",
            severity="High",
            recommendation="Remove external IP.",
        )
        assert finding["project_id"] == PROJECT_ID
        assert finding["scan_timestamp"] == SCAN_TIMESTAMP
        assert finding["status"] == "open"
        assert finding["check_id"] == "CG-001"
        assert finding["severity"] == "High"
        assert finding["category"] == "Security"


# ---------------------------------------------------------------------------
# check_vm_public_ip  (CG-001)
# ---------------------------------------------------------------------------

class TestCheckVmPublicIp:
    def test_wrong_asset_type_returns_empty(self):
        asset = make_asset("compute.googleapis.com/Firewall")
        findings = check_vm_public_ip(asset, {}, PROJECT_ID, SCAN_TIMESTAMP)
        assert findings == []

    def test_vm_with_public_ip_returns_finding(self):
        asset = make_asset("compute.googleapis.com/Instance")
        resource_data = {
            "networkInterfaces": [
                {"accessConfigs": [{"natIP": "34.1.2.3"}]}
            ],
            "zone": "zones/us-central1-a",
        }
        findings = check_vm_public_ip(asset, resource_data, PROJECT_ID, SCAN_TIMESTAMP)
        assert len(findings) == 1
        assert findings[0]["check_id"] == "CG-001"
        assert findings[0]["severity"] == "High"

    def test_vm_without_public_ip_returns_empty(self):
        asset = make_asset("compute.googleapis.com/Instance")
        resource_data = {
            "networkInterfaces": [{"accessConfigs": []}],
            "zone": "zones/us-central1-a",
        }
        findings = check_vm_public_ip(asset, resource_data, PROJECT_ID, SCAN_TIMESTAMP)
        assert findings == []

    def test_vm_with_no_network_interfaces_returns_empty(self):
        asset = make_asset("compute.googleapis.com/Instance")
        findings = check_vm_public_ip(asset, {}, PROJECT_ID, SCAN_TIMESTAMP)
        assert findings == []

    def test_multiple_interfaces_only_one_finding(self):
        asset = make_asset("compute.googleapis.com/Instance")
        resource_data = {
            "networkInterfaces": [
                {"accessConfigs": [{"natIP": "34.1.2.3"}]},
                {"accessConfigs": [{"natIP": "34.1.2.4"}]},
            ]
        }
        findings = check_vm_public_ip(asset, resource_data, PROJECT_ID, SCAN_TIMESTAMP)
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# check_firewall_open_ingress  (CG-002)
# ---------------------------------------------------------------------------

class TestCheckFirewallOpenIngress:
    def test_wrong_asset_type_returns_empty(self):
        asset = make_asset("compute.googleapis.com/Instance")
        findings = check_firewall_open_ingress(asset, {}, PROJECT_ID, SCAN_TIMESTAMP)
        assert findings == []

    def test_open_ingress_returns_finding(self):
        asset = make_asset("compute.googleapis.com/Firewall")
        resource_data = {"direction": "INGRESS", "sourceRanges": ["0.0.0.0/0"]}
        findings = check_firewall_open_ingress(asset, resource_data, PROJECT_ID, SCAN_TIMESTAMP)
        assert len(findings) == 1
        assert findings[0]["check_id"] == "CG-002"
        assert findings[0]["severity"] == "High"

    def test_restricted_ingress_returns_empty(self):
        asset = make_asset("compute.googleapis.com/Firewall")
        resource_data = {"direction": "INGRESS", "sourceRanges": ["10.0.0.0/8"]}
        findings = check_firewall_open_ingress(asset, resource_data, PROJECT_ID, SCAN_TIMESTAMP)
        assert findings == []

    def test_egress_with_open_range_returns_empty(self):
        asset = make_asset("compute.googleapis.com/Firewall")
        resource_data = {"direction": "EGRESS", "sourceRanges": ["0.0.0.0/0"]}
        findings = check_firewall_open_ingress(asset, resource_data, PROJECT_ID, SCAN_TIMESTAMP)
        assert findings == []

    def test_missing_source_ranges_returns_empty(self):
        asset = make_asset("compute.googleapis.com/Firewall")
        resource_data = {"direction": "INGRESS"}
        findings = check_firewall_open_ingress(asset, resource_data, PROJECT_ID, SCAN_TIMESTAMP)
        assert findings == []


# ---------------------------------------------------------------------------
# check_missing_labels  (CG-003)
# ---------------------------------------------------------------------------

class TestCheckMissingLabels:
    def test_all_labels_present_returns_empty(self):
        asset = make_asset("compute.googleapis.com/Instance")
        resource_data = {"labels": {"env": "prod", "owner": "platform-team"}}
        findings = check_missing_labels(asset, resource_data, PROJECT_ID, SCAN_TIMESTAMP)
        assert findings == []

    def test_missing_one_label_returns_finding(self):
        asset = make_asset("compute.googleapis.com/Instance")
        resource_data = {"labels": {"env": "prod"}}
        findings = check_missing_labels(asset, resource_data, PROJECT_ID, SCAN_TIMESTAMP)
        assert len(findings) == 1
        assert "owner" in findings[0]["finding_title"]

    def test_missing_all_labels_returns_finding(self):
        asset = make_asset("compute.googleapis.com/Instance")
        resource_data = {}
        findings = check_missing_labels(asset, resource_data, PROJECT_ID, SCAN_TIMESTAMP)
        assert len(findings) == 1
        assert findings[0]["check_id"] == "CG-003"
        assert findings[0]["severity"] == "Medium"

    def test_finding_lists_all_missing_labels(self):
        asset = make_asset("compute.googleapis.com/Disk")
        resource_data = {"labels": {}}
        findings = check_missing_labels(asset, resource_data, PROJECT_ID, SCAN_TIMESTAMP)
        title = findings[0]["finding_title"]
        assert "env" in title
        assert "owner" in title

    def test_applies_to_any_asset_type(self):
        asset = make_asset("compute.googleapis.com/Firewall")
        resource_data = {}
        findings = check_missing_labels(asset, resource_data, PROJECT_ID, SCAN_TIMESTAMP)
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# check_unattached_disk  (CG-004)
# ---------------------------------------------------------------------------

class TestCheckUnattachedDisk:
    def test_wrong_asset_type_returns_empty(self):
        asset = make_asset("compute.googleapis.com/Instance")
        findings = check_unattached_disk(asset, {}, PROJECT_ID, SCAN_TIMESTAMP)
        assert findings == []

    def test_unattached_disk_returns_finding(self):
        asset = make_asset("compute.googleapis.com/Disk")
        resource_data = {"zone": "zones/us-central1-a"}
        findings = check_unattached_disk(asset, resource_data, PROJECT_ID, SCAN_TIMESTAMP)
        assert len(findings) == 1
        assert findings[0]["check_id"] == "CG-004"
        assert findings[0]["category"] == "Cost"
        assert findings[0]["severity"] == "Medium"

    def test_attached_disk_returns_empty(self):
        asset = make_asset("compute.googleapis.com/Disk")
        resource_data = {
            "users": ["projects/test/zones/us-central1-a/instances/my-vm"],
            "zone": "zones/us-central1-a",
        }
        findings = check_unattached_disk(asset, resource_data, PROJECT_ID, SCAN_TIMESTAMP)
        assert findings == []

    def test_unattached_disk_location_from_zone(self):
        asset = make_asset("compute.googleapis.com/Disk")
        resource_data = {"zone": "zones/europe-west1-b"}
        findings = check_unattached_disk(asset, resource_data, PROJECT_ID, SCAN_TIMESTAMP)
        assert findings[0]["resource_location"] == "zones/europe-west1-b"

    def test_unattached_disk_unknown_location_fallback(self):
        asset = make_asset("compute.googleapis.com/Disk")
        findings = check_unattached_disk(asset, {}, PROJECT_ID, SCAN_TIMESTAMP)
        assert findings[0]["resource_location"] == "unknown"
