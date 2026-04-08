import os
from datetime import datetime, timezone
from typing import Any
from google.cloud import asset_v1
from rules import (
    check_vm_public_ip,
    check_firewall_open_ingress,
    check_missing_labels,
    check_unattached_disk,
)

PROJECT_ID: str = os.environ.get("GOOGLE_CLOUD_PROJECT", "your-project-id")


def run_scan() -> list[dict[str, Any]]:
    client = asset_v1.AssetServiceClient()

    scope: str = f"projects/{PROJECT_ID}"

    request = asset_v1.ListAssetsRequest(
        parent=scope,
        asset_types=[
            "compute.googleapis.com/Instance",
            "compute.googleapis.com/Firewall",
            "compute.googleapis.com/Disk",
        ],
        content_type=asset_v1.ContentType.RESOURCE,
    )

    findings: list[dict[str, Any]] = []
    scan_timestamp: str = datetime.now(timezone.utc).isoformat()

    for asset in client.list_assets(request=request):
        resource_data: dict[str, Any] = (
            asset.resource.data if asset.resource and asset.resource.data else {}
        )

        findings.extend(
            check_vm_public_ip(asset, resource_data, PROJECT_ID, scan_timestamp)
        )
        findings.extend(
            check_firewall_open_ingress(asset, resource_data, PROJECT_ID, scan_timestamp)
        )
        findings.extend(
            check_missing_labels(asset, resource_data, PROJECT_ID, scan_timestamp)
        )
        findings.extend(
            check_unattached_disk(asset, resource_data, PROJECT_ID, scan_timestamp)
        )

    return findings
