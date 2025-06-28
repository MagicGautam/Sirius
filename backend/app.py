# backend/app.py

from flask import Flask, request, jsonify
from backend.config import DevelopmentConfig
from backend.extensions import db  # Import the SQLAlchemy instance
from backend.services.sast_service import SastService
from backend.models.sast_models import SastFinding
import logging

app = Flask(__name__)
app.config.from_object(DevelopmentConfig) 

db.init_app(app)  # Initialize the SQLAlchemy instance with the Flask app

sast_service = SastService(app)

with app.app_context():
    db.create_all()
    logging.getLogger(__name__).info("All database tables initialized.")

@app.route('/api/ingest/<scan_type>', methods=['POST'])
def ingest_report(scan_type):
    if not request.is_json:
        return jsonify({"error": "Invalid JSON format"}), 400
    
    report_data = request.get_json()

    try:
        if scan_type == 'sast':
            new_count, total_count = sast_service.ingest_semgrep_report(report_data)
            return jsonify({
                "message": f"Ingested {new_count} new SAST findings.",
                "total_findings_in_report": total_count,
                "newly_ingested_count": new_count
                }), 200
        else:
            return jsonify({"error": f"Scan type '{scan_type}' not yet supported for detailed parsing. No data ingested."}), 400
        

    except Exception as e:
        # sast_db.session.rollback() # Rollback is handled within sast_service for its own session
        import logging
        logging.basicConfig()
        logging.getLogger('flask.app').setLevel(logging.ERROR)
        app.logger.error(f"Error ingesting {scan_type} report: {e}", exc_info=True)
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
    import logging
    logging.basicConfig()
    logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)  # Log SQL Statements
    app.run(debug=True)
# This will run the Flask app on port 8000 with debug mode enabled.
# You can access the API at http://localhost:8000/api/ingest/sast
# and http://localhost:8000/api/findings/sast to retrieve SAST findings.