from google.cloud import bigquery

DATASET_ID = "cloudguard"
TABLE_ID = "findings"


def write_findings_to_bigquery(project_id, findings):
    if not findings:
        return []

    client = bigquery.Client(project=project_id)
    table_ref = f"{project_id}.{DATASET_ID}.{TABLE_ID}"

    errors = client.insert_rows_json(table_ref, findings)

    if errors:
        print("BigQuery insert errors:", errors)
    else:
        print(f"Inserted {len(findings)} findings into {table_ref}")

    return errors
