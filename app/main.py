import os
from flask import Flask, jsonify
from scanner import run_scan
from bigquery_writer import write_findings_to_bigquery

app = Flask(__name__)

PROJECT_ID = os.environ.get("GOOGLE_CLOUD_PROJECT", "cloudguard-platform")

@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "message": "CloudGuard is running"
    }), 200

@app.route("/scan", methods=["GET"])
def scan():
    findings = run_scan()
    errors = write_findings_to_bigquery(PROJECT_ID, findings)

    return jsonify({
        "status": "success",
        "finding_count": len(findings),
        "bigquery_errors": errors,
        "findings": findings
    }), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
