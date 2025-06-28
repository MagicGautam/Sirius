# backend/app.py

# backend/app.py
from flask import Flask, request, jsonify
from backend.config import DevelopmentConfig
from backend.extensions import db
from backend.services.sast_service import SastService
from backend.models.sast_models import SastFinding
import logging
import json # Import json for pretty printing

app = Flask(__name__)
app.config.from_object(DevelopmentConfig)

# Ensure app.logger is set up
app.logger.setLevel(logging.DEBUG)

db.init_app(app)

sast_service = SastService(db)

with app.app_context():
    db.create_all()
    app.logger.info("All database tables created/updated across binds.")


@app.route('/api/ingest/<scan_type>', methods=['POST'])
def ingest_report(scan_type):
    print(f"\n--- API CALL: /api/ingest/{scan_type} ---") # DIRECT PRINT
    app.logger.debug(f"Ingest API called for scan_type: {scan_type}")

    if not request.is_json:
        app.logger.warning("Request is not JSON, returning 400.")
        print("--- DEBUG: Request is NOT JSON. ---") # DIRECT PRINT
        return jsonify({"error": "Request must be JSON"}), 400

    report_data = request.get_json()
    print(f"--- DEBUG: app.py received raw JSON from request.get_json(): {report_data}") # DIRECT PRINT

    if report_data is None:
        app.logger.error("request.get_json() returned None, likely invalid or empty JSON body.")
        print("--- DEBUG: report_data is NONE after get_json(). ---") # DIRECT PRINT
        return jsonify({"error": "No data provided in report or invalid JSON format"}), 400
    if not isinstance(report_data, dict):
        app.logger.error(f"request.get_json() returned non-dictionary type: {type(report_data)}")
        print(f"--- DEBUG: report_data is NOT a dict. Type: {type(report_data)}. Value: {report_data} ---") # DIRECT PRINT
        return jsonify({"error": "Invalid JSON format: expected object"}), 400

    try:
        print(f"--- DEBUG: app.py calling sast_service.ingest_semgrep_report with dict keys: {report_data.keys()} ---") # DIRECT PRINT
        new_count, total_count = sast_service.ingest_semgrep_report(report_data)
        app.logger.info(f"Ingested {new_count} new SAST findings.")
        return jsonify({
            "message": f"Successfully ingested {new_count} new SAST findings (out of {total_count} in report).",
            "total_findings_in_report": total_count,
            "newly_ingested_count": new_count
        }), 200

    except Exception as e:
        app.logger.error(f"Error ingesting {scan_type} report: {e}", exc_info=True)
        print(f"--- DEBUG: Exception caught in app.py: {e}") # DIRECT PRINT
        return jsonify({"error": f"Failed to ingest report for {scan_type}. Details: {str(e)}"}), 500    

@app.route('/api/findings/<scan_type>', methods=['GET'])
def get_findings(scan_type):
    if scan_type == 'sast':
        findings = sast_service.get_all_findings()
        return jsonify(findings), 200
    else:
        return jsonify({"error": f"Retrieval for scan type '{scan_type}' not yet implemented."}), 400
    

@app.route('/')
def home():
    return "DevSecOps Vulnerability Dashboard Backend - Online!"


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)  # Log SQL Statements
    app.run(debug=True)
# This will run the Flask app on port 8000 with debug mode enabled.
# You can access the API at http://localhost:8000/api/ingest/sast
# and http://localhost:8000/api/findings/sast to retrieve SAST findings.