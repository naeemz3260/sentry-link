"""
SentryLink — URL Security & Phishing Detection System
Flask application entry point.
"""
import os
import io
import json

from flask import Flask, request, jsonify, render_template, send_file

import database
from analyzer.scorer import run_full_scan

app = Flask(__name__)
database.init_db()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def api_scan():
    payload = request.get_json(silent=True) or {}
    raw_url = (payload.get("url") or "").strip()

    if not raw_url:
        return jsonify({"error": "Please provide a URL to scan."}), 400
    if len(raw_url) > 2048:
        return jsonify({"error": "URL is too long to process."}), 400

    try:
        result = run_full_scan(raw_url)
    except Exception as e:
        return jsonify({"error": f"Scan failed: {e}"}), 500

    scan_id = database.save_scan(result)
    result["id"] = scan_id
    return jsonify(result)


@app.route("/api/history", methods=["GET"])
def api_history():
    limit = request.args.get("limit", default=50, type=int)
    return jsonify(database.list_scans(limit=limit))


@app.route("/api/history/<int:scan_id>", methods=["GET"])
def api_history_detail(scan_id):
    scan = database.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found."}), 404
    return jsonify(scan)


@app.route("/api/history/<int:scan_id>", methods=["DELETE"])
def api_history_delete(scan_id):
    ok = database.delete_scan(scan_id)
    if not ok:
        return jsonify({"error": "Scan not found."}), 404
    return jsonify({"deleted": scan_id})


@app.route("/api/history", methods=["DELETE"])
def api_history_clear():
    count = database.clear_history()
    return jsonify({"cleared": count})


@app.route("/api/history/<int:scan_id>/report", methods=["GET"])
def api_history_report(scan_id):
    """Export a single scan as a downloadable JSON report."""
    scan = database.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found."}), 404

    buf = io.BytesIO(json.dumps(scan["result"], indent=2).encode("utf-8"))
    buf.seek(0)
    return send_file(
        buf,
        mimetype="application/json",
        as_attachment=True,
        download_name=f"sentrylink-report-{scan_id}.json",
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug, host="0.0.0.0", port=port)
