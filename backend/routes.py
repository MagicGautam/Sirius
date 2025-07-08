from flask import Blueprint, request, jsonify, current_app
import logging
import hashlib
from backend.models import db
from backend.models.sast_models import SastFinding
# from backend.models.container_models import ContainerFinding # Uncomment when ready

api_bp = Blueprint('api', __name__, url_prefix='/api')

logger = logging.getLogger(__name__)

@api_bp.route('/ingest/<scan_type>', methods=['POST'])
def ingest_report(scan_type):
    # Access services and logger via current_app
    sast_service = current_app.sast_service
    container_service = current_app.container_service # Assuming you'll add this soon
    current_app.logger.debug(f"Ingest API called for scan_type: {scan_type}")

    if not request.is_json:
        current_app.logger.warning("Request is not JSON, returning 400.")
        return jsonify({"error": "Request must be JSON"}), 400

    report_data = request.get_json()

    if report_data is None:
        current_app.logger.error("request.get_json() returned None, likely invalid or empty JSON body.")
        return jsonify({"error": "No data provided in report or invalid JSON format"}), 400
    if not isinstance(report_data, dict):
        current_app.logger.error(f"request.get_json() returned non-dictionary type: {type(report_data)}")
        return jsonify({"error": "Invalid JSON format: expected object"}), 400

    try:
        new_count, total_count = 0, 0
        if scan_type == 'sast':
            # print removed, use logger debug
            current_app.logger.debug(f"Calling sast_service.ingest_semgrep_report with dict keys: {report_data.keys()}")
            new_count, total_count = sast_service.ingest_semgrep_report(report_data)
            current_app.logger.info(f"Ingested {new_count} new SAST findings.")
            message = f"Successfully ingested {new_count} new SAST findings (out of {total_count} in report)."
        elif scan_type == 'container':
            # This is where you would call your container_service
            current_app.logger.debug(f"Calling container_service.ingest_trivy_report with dict keys: {report_data.keys()}")
            # new_count, total_count = container_service.ingest_trivy_report(report_data) # Uncomment when implemented
            message = "Container report ingestion not yet fully implemented, but received." # Placeholder
            current_app.logger.info(f"Received container report, placeholder response.")
        else:
            current_app.logger.warning(f"Unsupported scan type for ingestion: {scan_type}")
            return jsonify({"error": f"Unsupported scan type '{scan_type}' for ingestion."}), 400

        return jsonify({
            "message": message,
            "total_findings_in_report": total_count,
            "newly_ingested_count": new_count
        }), 200

    except Exception as e:
        current_app.logger.error(f"Error ingesting {scan_type} report: {e}", exc_info=True)
        return jsonify({"error": f"Failed to ingest report for {scan_type}. Details: {str(e)}"}), 500    

@api_bp.route('/findings/<scan_type>', methods=['GET'])
def get_findings(scan_type):
    # Access services via current_app
    sast_service = current_app.sast_service
    # container_service = current_app.container_service # Uncomment when ready

    if scan_type == 'sast':
        findings = sast_service.get_all_findings()
        return jsonify(findings), 200
    elif scan_type == 'container':
        # FUTURE: Placeholder for container findings retrieval
        # findings = container_service.get_all_findings() # Uncomment when implemented
        return jsonify({"error": f"Retrieval for scan type '{scan_type}' not yet implemented."}), 501 # Not Implemented
    else:
        return jsonify({"error": f"Retrieval for scan type '{scan_type}' not yet implemented."}), 400


# --- API Endpoint for LLM Analysis ---
@api_bp.route('/llm/analyze/<scan_type>/<int:finding_id>', methods=['GET'])
def analyze_finding_with_llm(scan_type: str, finding_id: int):
    # Access services and logger via current_app
    llm_service = current_app.llm_service
    sast_service = current_app.sast_service # If you need sast_service for fetching
    # container_service = current_app.container_service # If you need for container findings
    current_app.logger.info(f"Received request to analyze {scan_type} finding ID: {finding_id} with LLM via Ollama.")

    # 1. Check if LLM service (Ollama connection) is ready
    if not llm_service.is_loaded():
        current_app.logger.warning("Ollama LLM service is not ready. Returning 503.")
        return jsonify({"error": "LLM service is not ready. Please ensure Ollama is running and accessible."}), 503

    finding_data = None
    finding_obj = None # Keep a reference to the SQLAlchemy object if updating it later

    # 2. Fetch the finding data from the database based on scan_type
    # Using current_app.db.session instead of db.session
    if scan_type == 'sast':
        # The app context is already active during a request, so no need for `with app.app_context()` here
        finding_obj = db.session.get(SastFinding, finding_id)
        if finding_obj:
            finding_data = finding_obj.to_dict()
    elif scan_type == 'container':
        from backend.models.container_models import ContainerFinding # Import model where used
        finding_obj = db.session.get(ContainerFinding, finding_id)
        if finding_obj:
            finding_data = finding_obj.to_dict()
        else:
             current_app.logger.warning(f"Container finding with ID {finding_id} not found.")
             return jsonify({"error": f"Container finding with ID {finding_id} not found."}), 404
    else:
        current_app.logger.warning(f"Unsupported scan type for LLM analysis: {scan_type}")
        return jsonify({"error": f"Unsupported scan type '{scan_type}' for LLM analysis."}), 400

    # 3. Handle case where finding is not found
    if not finding_data:
        current_app.logger.warning(f"Finding with ID {finding_id} not found for scan type {scan_type}.")
        return jsonify({"error": f"Finding with ID {finding_id} not found."}), 404
    
    # 4. Generate LLM prompt and analysis
    try:
        # Ask LLMService to generate the appropriate prompt for the scan type
        prompt = llm_service.generate_prompt(scan_type, finding_data)
        current_prompt_hash = hashlib.sha256(prompt.encode('utf-8')).hexdigest()

        # Check if the finding has already been analyzed and cached with this exact prompt
        if finding_obj and hasattr(finding_obj, 'llm_analysis_content') and \
           hasattr(finding_obj, 'llm_analysis_prompt_hash') and \
           finding_obj.llm_analysis_content and \
           finding_obj.llm_analysis_prompt_hash == current_prompt_hash:
            current_app.logger.info(f"LLM analysis for finding ID {finding_id} found in cache. Returning cached analysis.")
            return jsonify({
                "finding_id": finding_id,
                "scan_type": scan_type,
                "llm_analysis": finding_obj.llm_analysis_content
            }), 200
        
        current_app.logger.info(f"LLM analysis for finding ID {finding_id} not cached or prompt mismatch. Generating new analysis.")

        # Generating new analysis here
        llm_analysis = llm_service.generate_analysis(prompt)
        
        # Update the finding object with the new analysis and hash
        if finding_obj and hasattr(finding_obj, 'llm_analysis_content') and hasattr(finding_obj, 'llm_analysis_prompt_hash'):
            finding_obj.llm_analysis_content = llm_analysis
            finding_obj.llm_analysis_prompt_hash = current_prompt_hash
            db.session.add(finding_obj) # Add back to session in case it detached
            db.session.commit()
            current_app.logger.info(f"LLM analysis generated and saved for finding ID {finding_id}.")          
        else:
            current_app.logger.warning(f"Finding object for {scan_type} ID {finding_id} does not support LLM analysis fields. Analysis not saved to DB.")

        return jsonify({"finding_id": finding_id, "scan_type": scan_type, "llm_analysis": llm_analysis}), 200
    
    except Exception as e:
        current_app.logger.error(f"Error during LLM analysis for finding {finding_id}: {e}", exc_info=True)
        return jsonify({"error": f"Failed to generate LLM analysis: {str(e)}"}), 500

@api_bp.route('/')
def home():
    return "Sirius is watching!"