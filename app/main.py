from flask import Flask, jsonify
from scanner import run_scan

app = Flask(__name__)

@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "message": "CloudGuard is running"
    }), 200

@app.route("/scan", methods=["GET"])
def scan():
    findings = run_scan()
    return jsonify({
        "status": "success",
        "finding_count": len(findings),
        "findings": findings
    }), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
