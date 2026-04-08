from typing import Any


def build_finding(
    project_id: str,
    scan_timestamp: str,
    resource_name: str,
    resource_type: str,
    resource_location: str,
    check_id: str,
    finding_title: str,
    category: str,
    severity: str,
    recommendation: str,
) -> dict[str, str]:
    return {
        "scan_timestamp": scan_timestamp,
        "project_id": project_id,
        "resource_name": resource_name,
        "resource_type": resource_type,
        "resource_location": resource_location,
        "check_id": check_id,
        "finding_title": finding_title,
        "category": category,
        "severity": severity,
        "status": "open",
        "recommendation": recommendation,
    }


def check_vm_public_ip(
    asset: Any,
    resource_data: dict[str, Any],
    project_id: str,
    scan_timestamp: str,
) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []

    if asset.asset_type != "compute.googleapis.com/Instance":
        return findings

    interfaces = resource_data.get("networkInterfaces", [])

    for interface in interfaces:
        access_configs = interface.get("accessConfigs", [])
        if access_configs:
            findings.append(
                build_finding(
                    project_id=project_id,
                    scan_timestamp=scan_timestamp,
                    resource_name=asset.name,
                    resource_type=asset.asset_type,
                    resource_location=resource_data.get("zone", "unknown"),
                    check_id="CG-001",
                    finding_title="VM has public IP",
                    category="Security",
                    severity="High",
                    recommendation=(
                        "Remove external IP and use private access patterns "
                        "such as IAP, load balancing, or bastion alternatives."
                    ),
                )
            )
            break

    return findings


def check_firewall_open_ingress(
    asset: Any,
    resource_data: dict[str, Any],
    project_id: str,
    scan_timestamp: str,
) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []

    if asset.asset_type != "compute.googleapis.com/Firewall":
        return findings

    direction: str = resource_data.get("direction", "")
    source_ranges: list[str] = resource_data.get("sourceRanges", [])

    if direction == "INGRESS" and "0.0.0.0/0" in source_ranges:
        findings.append(
            build_finding(
                project_id=project_id,
                scan_timestamp=scan_timestamp,
                resource_name=asset.name,
                resource_type=asset.asset_type,
                resource_location="global",
                check_id="CG-002",
                finding_title="Firewall allows 0.0.0.0/0 ingress",
                category="Security",
                severity="High",
                recommendation="Restrict source ranges to trusted IPs or internal CIDR ranges.",
            )
        )

    return findings


def check_missing_labels(
    asset: Any,
    resource_data: dict[str, Any],
    project_id: str,
    scan_timestamp: str,
) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []

    labels: dict[str, str] = resource_data.get("labels", {})
    required_labels: list[str] = ["env", "owner"]

    missing: list[str] = [label for label in required_labels if label not in labels]

    if missing:
        findings.append(
            build_finding(
                project_id=project_id,
                scan_timestamp=scan_timestamp,
                resource_name=asset.name,
                resource_type=asset.asset_type,
                resource_location=resource_data.get("zone", resource_data.get("region", "unknown")),
                check_id="CG-003",
                finding_title=f"Missing required labels: {', '.join(missing)}",
                category="Governance",
                severity="Medium",
                recommendation=(
                    "Apply consistent labels such as env and owner "
                    "for governance, reporting, and accountability."
                ),
            )
        )

    return findings


def check_unattached_disk(
    asset: Any,
    resource_data: dict[str, Any],
    project_id: str,
    scan_timestamp: str,
) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []

    if asset.asset_type != "compute.googleapis.com/Disk":
        return findings

    users: list[str] = resource_data.get("users", [])

    if not users:
        findings.append(
            build_finding(
                project_id=project_id,
                scan_timestamp=scan_timestamp,
                resource_name=asset.name,
                resource_type=asset.asset_type,
                resource_location=resource_data.get("zone", "unknown"),
                check_id="CG-004",
                finding_title="Unattached persistent disk",
                category="Cost",
                severity="Medium",
                recommendation=(
                    "Review whether the disk is still needed. "
                    "Remove unused disks to reduce waste."
                ),
            )
        )

    return findings
