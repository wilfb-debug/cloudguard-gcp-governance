import os
from typing import Any
from flask import Flask, jsonify, request
from scanner import run_scan
from bigquery_writer import write_findings_to_bigquery

app = Flask(__name__)

PROJECT_ID: str = os.environ.get("GOOGLE_CLOUD_PROJECT", "cloudguard-platform")
VERSION: str = "1.0.0"

VALID_SEVERITIES: set[str] = {"High", "Medium", "Low"}
VALID_CATEGORIES: set[str] = {"Security", "Cost", "Governance"}


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "message": "CloudGuard is running",
        "version": VERSION,
        "endpoints": ["/health", "/scan", "/findings"],
    }), 200


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "version": VERSION,
    }), 200


@app.route("/scan", methods=["GET"])
def scan():
    findings: list[dict[str, Any]] = run_scan()
    errors: list[Any] = write_findings_to_bigquery(PROJECT_ID, findings)

    return jsonify({
        "status": "success",
        "finding_count": len(findings),
        "bigquery_errors": errors,
        "findings": findings,
    }), 200


@app.route("/findings", methods=["GET"])
def findings():
    severity: str | None = request.args.get("severity")
    category: str | None = request.args.get("category")
    check_id: str | None = request.args.get("check_id")

    try:
        limit: int = min(int(request.args.get("limit", 50)), 200)
        offset: int = max(int(request.args.get("offset", 0)), 0)
    except ValueError:
        return jsonify({"error": "limit and offset must be integers"}), 400

    if severity and severity not in VALID_SEVERITIES:
        return jsonify({"error": f"severity must be one of {sorted(VALID_SEVERITIES)}"}), 400

    if category and category not in VALID_CATEGORIES:
        return jsonify({"error": f"category must be one of {sorted(VALID_CATEGORIES)}"}), 400

    all_findings: list[dict[str, Any]] = run_scan()

    filtered: list[dict[str, Any]] = [
        f for f in all_findings
        if (not severity or f["severity"] == severity)
        and (not category or f["category"] == category)
        and (not check_id or f["check_id"] == check_id)
    ]

    total: int = len(filtered)
    page: list[dict[str, Any]] = filtered[offset: offset + limit]

    return jsonify({
        "total": total,
        "limit": limit,
        "offset": offset,
        "filters": {
            "severity": severity,
            "category": category,
            "check_id": check_id,
        },
        "findings": page,
    }), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
