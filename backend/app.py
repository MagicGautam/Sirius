# backend/app.py

# backend/app.py
from flask import Flask, request, jsonify
from backend.config import DevelopmentConfig
from backend.extensions import db
from backend.services.sast_service import SastService
from backend.models.sast_models import SastFinding
from backend.services.llm_service import LLMService # Import the new LLM service
import logging
import hashlib
import json # Import json for pretty printing

app = Flask(__name__)
app.config.from_object(DevelopmentConfig)

# Ensure app.logger is set up
app.logger.setLevel(logging.DEBUG)

db.init_app(app)
llm_service = LLMService(model_name="gemma3:1b")
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


# --- NEW: API Endpoint for LLM Analysis ---
@app.route('/api/llm/analyze/<scan_type>/<int:finding_id>', methods=['GET'])
def analyze_finding_with_llm(scan_type: str, finding_id: int):
    """
    API endpoint to trigger LLM analysis for a specific security finding.
    The LLM processes the finding details and provides a human-readable analysis and fix.
    """
    app.logger.info(f"Received request to analyze {scan_type} finding ID: {finding_id} with LLM via Ollama.")

    # 1. Check if LLM service (Ollama connection) is ready
    if not llm_service.is_loaded():
        app.logger.warning("Ollama LLM service is not ready. Returning 503.")
        return jsonify({"error": "LLM service is not ready. Please ensure Ollama is running and accessible."}), 503 # Service Unavailable

    finding_data = None
    # 2. Fetch the finding data from the database based on scan_type
    if scan_type == 'sast':
        with app.app_context(): # Ensure we are in an application context for DB operations
            # Query the SastFinding model to get the finding by its ID
            sast_finding_obj = SastFinding.query.get(finding_id)
            if sast_finding_obj:
                # Convert the SQLAlchemy model object to a dictionary for LLM processing
                finding_data = sast_finding_obj.to_dict()
    elif scan_type == 'dast' or scan_type == 'sca':
        # FUTURE: Placeholder for DAST and SCA.
        # You would query your DASTFinding or ScaFinding models here.
        app.logger.warning(f"Analysis for scan type '{scan_type}' is not yet fully implemented for database retrieval.")
        return jsonify({"error": f"Retrieval for scan type '{scan_type}' is not yet implemented."}), 501 # Not Implemented
    else:
        app.logger.warning(f"Unsupported scan type for LLM analysis: {scan_type}")
        return jsonify({"error": f"Unsupported scan type '{scan_type}' for LLM analysis."}), 400

    # 3. Handle case where finding is not found
    if not finding_data:
        app.logger.warning(f"Finding with ID {finding_id} not found for scan type {scan_type}.")
        return jsonify({"error": f"Finding with ID {finding_id} not found."}), 404

    #5th july Commit: 
    
    # 4. Generate LLM prompt and analysis

    # Check if the finding has already been analyzed and cached
    try:
        # Ask LLMService to generate the appropriate prompt for the scan type
        prompt = llm_service.generate_prompt(scan_type, finding_data)
        current_prompt_hash=hashlib.sha256(prompt.encode('utf-8')).hexdigest()

        if sast_finding_obj and sast_finding_obj.llm_analysis_content and \
            sast_finding_obj.llm_analysis_prompt_hash == current_prompt_hash:
            app.logger.info(f"LLM analysis for finding ID {finding_id} found in cache. Returning cached analysis.")
            return jsonify({
                "finding_id": finding_id,
                "scan_type": scan_type,
                "llm_analysis": sast_finding_obj.llm_analysis_content
            }), 200
        app.logger.info(f"LLM analysis for finding ID {finding_id} not found in cache. Generating new analysis.")

    # Case where finding is not found or prompt hash does not match

        # Generating new analysis here
        llm_analysis = llm_service.generate_analysis(prompt)
        
        with app.app_context():
            sast_finding_obj.llm_analysis_content= llm_analysis
            sast_finding_obj.llm_analysis_prompt_hash = current_prompt_hash
            db.session.add(sast_finding_obj)
            db.session.commit()
            app.logger.info(f"LLM analysis generated for finding ID {finding_id}.")          
        
        return jsonify({"finding_id": finding_id, "scan_type": scan_type, "llm_analysis": llm_analysis}), 200
    
    except Exception as e:
        app.logger.error(f"Error during LLM analysis for finding {finding_id}: {e}", exc_info=True)
        return jsonify({"error": f"Failed to generate LLM analysis: {str(e)}"}), 500



@app.route('/')
def home():
    return "Sirius is watching!"


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)  # Log SQL Statements
    app.run(debug=True)
# This will run the Flask app on port 8000 with debug mode enabled.
# You can access the API at http://localhost:8000/api/ingest/sast
# and http://localhost:8000/api/findings/sast to retrieve SAST findings.