from typing import Any
from google.cloud import bigquery

DATASET_ID: str = "cloudguard"
TABLE_ID: str = "findings"


def write_findings_to_bigquery(
    project_id: str,
    findings: list[dict[str, Any]],
) -> list[Any]:
    if not findings:
        return []

    client = bigquery.Client(project=project_id)
    table_ref: str = f"{project_id}.{DATASET_ID}.{TABLE_ID}"

    errors: list[Any] = client.insert_rows_json(table_ref, findings)

    if errors:
        print("BigQuery insert errors:", errors)
    else:
        print(f"Inserted {len(findings)} findings into {table_ref}")

    return errors
