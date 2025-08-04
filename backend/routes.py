from flask import Blueprint, request, jsonify, current_app
import logging
# hashlib is generally not needed directly in routes for current logic.
# from backend.models import db # No longer directly used here
# from backend.models.sast_models import SastFinding # No longer directly used here
# from backend.models.container_models import ContainerFinding # No longer directly used here

# Removed unused imports from the top (hashlib and model imports) as services handle them.

api_bp = Blueprint('api', __name__, url_prefix='/api')

logger = logging.getLogger(__name__) # Keep this logger, it's specific to the blueprint

# -- SAST Scans API Endpoints ---
@api_bp.route('/sast/scans', methods=['POST'])
def ingest_sast_scan():
    sast_service = current_app.sast_service
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
    
    report_data = request.get_json()
    project_name = report_data.get('project_name')

    if not report_data or not project_name:
        return jsonify({"error": "Missing 'project_name' or 'report_data' in request body."}), 400
    
    # We pass the project_name as a separate argument to the service
    new_count, total_count = sast_service.ingest_sast_report(report_data, project_name)
    message = f"Successfully ingested {new_count} new SAST findings (out of {total_count} in report)."
    return jsonify({"message": message, "newly_ingested_count": new_count, "total_findings_in_report": total_count}), 200

@api_bp.route('/sast/scans', methods=['GET'])
def get_all_sast_scans():
    sast_service = current_app.sast_service
    if not sast_service:
        current_app.logger.error("SAST service not initialized in current_app.")
        return jsonify({"error": "SAST service not available."}), 500

    # Assuming a new get_all_scans method is added to SastService
    scans = sast_service.get_all_scans()
    return jsonify(scans), 200

@api_bp.route('/sast/scans/<int:scan_id>/findings', methods=['GET'])
def get_findings_for_sast_scan(scan_id):
    sast_service = current_app.sast_service
    if not sast_service:
        return jsonify({"error": "SAST service not initialized."}), 500
    
    findings = sast_service.get_findings_for_scan(scan_id)
    if findings is None:
        return jsonify({"error": f"SastScan with ID {scan_id} not found."}), 404
    
    return jsonify(findings), 200

@api_bp.route('/sast/findings/<int:finding_id>', methods=['GET'])
def get_sast_finding_by_id(finding_id: int):
    sast_service = current_app.sast_service
    if not sast_service:
        return jsonify({"error": "SAST service not initialized."}), 500

    finding = sast_service.get_findings_by_id(finding_id)
    if not finding:
        return jsonify({"error": f"SAST finding with ID {finding_id} not found."}), 404
    
    return jsonify(finding), 200



# -- Container Scans API Endpoints ---    

@api_bp.route('/container/scans', methods=['POST'])
def ingest_container_scan():
    container_service = current_app.container_service
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
    report_data = request.get_json()
    if not report_data:
        return jsonify({"error": "No data provided in report or invalid JSON format"}), 400
    
    # We'll need to update the container ingestion to accept a project name
    # For now, let's assume it's in the body or we don't need it for container scans
    # As we discussed, the container ingest is already refactored to handle this.
    new_count, total_count = container_service.ingest_trivy_report(report_data)
    message = f"Successfully ingested {new_count} new Container findings (out of {total_count} in report)."
    return jsonify({"message": message, "newly_ingested_count": new_count, "total_findings_in_report": total_count}), 200


@api_bp.route('/container/scans', methods=['GET'])
def get_container_scans():
    # Access container service via current_app
    container_service = current_app.container_service 

    if not container_service:
        current_app.logger.error("Container service not initialized in current_app.")
        return jsonify({"error": "Container service not available."}), 500

    scans = container_service.get_all_scans()
    return jsonify(scans), 200    

@api_bp.route('/container/scans/<string:artifactname>', methods=['GET'])
def get_container_scan_by_artifact_name(artifactname: str):
    # Access container service via current_app
    container_service = current_app.container_service 

    if not container_service:
        current_app.logger.error("Container service not initialized in current_app.")
        return jsonify({"error": "Container service not available."}), 500

    finding = container_service.get_scan_by_artifact_name(artifactname)
    if not finding:
        return jsonify({"error": f"Container Scan with Artifact-Name {artifactname} not found."}), 404

    return jsonify(finding), 200

@api_bp.route('/container/findings/<int:finding_id>', methods=['GET'])
def get_container_finding_by_id(finding_id: int):
    # Access container service via current_app
    container_service = current_app.container_service 

    if not container_service:
        current_app.logger.error("Container service not initialized in current_app.")
        return jsonify({"error": "Container service not available."}), 500

    finding = container_service.get_finding_by_id(finding_id)
    if not finding:
        return jsonify({"error": f"Container finding with ID {finding_id} not found."}), 404

    return jsonify(finding), 200

@api_bp.route('/container/scans/<string:identifier>/findings', methods=['GET'])
def get_findings_for_container_scan(identifier: str):
    """
    Retrieves all findings for a specific container scan, using either
    the scan's ID or its artifact name.
    """
    container_service = current_app.container_service
    if not container_service:
        return jsonify({"error": "Container service not initialized."}), 500
        
    try:
        findings = container_service.get_findings_for_scan(identifier)
        
        if findings is None:
            # This indicates the scan was not found
            return jsonify({"error": f"ContainerScan with ID or Artifact Name '{identifier}' not found."}), 404
        
        return jsonify(findings), 200

    except Exception as e:
        current_app.logger.error(f"Error fetching findings for scan {identifier}: {e}", exc_info=True)
        return jsonify({"error": "An internal server error occurred."}), 500
    

# --- Consolidated API Endpoint for LLM Analysis ---
@api_bp.route('/llm/analyze/<scan_type>/<int:finding_id>', methods=['GET'])
def analyze_finding_with_llm(scan_type: str, finding_id: int):
    # Access services and logger via current_app
    llm_service = current_app.llm_service
    sast_service = current_app.sast_service
    container_service = current_app.container_service 
    current_app.logger.info(f"Received request to analyze {scan_type} finding ID: {finding_id} with LLM via Ollama.")

    # 1. Check if LLM service (Ollama connection) is ready
    if not llm_service or not llm_service.is_loaded(): # Added `llm_service` check for robustness
        current_app.logger.warning("Ollama LLM service is not ready. Returning 503.")
        return jsonify({"error": "LLM service is not ready. Please ensure Ollama is running and accessible."}), 503

    # 2. Delegate to the appropriate service for caching/generation logic
    try:
        analysis_data = None
        status_code = 200 

        if scan_type == 'sast':
            if not sast_service:
                current_app.logger.error("SAST service not initialized for LLM analysis.")
                return jsonify({"error": "SAST service not available for LLM analysis."}), 500
            # Call the service method, it handles all the LLM analysis logic now
            analysis_data, status_code = sast_service.get_or_generate_llm_analysis_for_finding(finding_id)
        elif scan_type == 'container':
            if not container_service:
                current_app.logger.error("Container service not initialized for LLM analysis.")
                return jsonify({"error": "Container service not available for LLM analysis."}), 500
            # Assumes container_service also has get_or_generate_llm_analysis_for_finding
            analysis_data, status_code = container_service.get_or_generate_llm_analysis_for_finding(finding_id)
        else:
            current_app.logger.warning(f"Unsupported scan type for LLM analysis: {scan_type}")
            return jsonify({"error": f"Unsupported scan type '{scan_type}' for LLM analysis."}), 400

        # 3. Return the analysis data and status from the service
        return jsonify(analysis_data), status_code

    except Exception as e:
        current_app.logger.error(f"Error during LLM analysis request for finding {finding_id}: {e}", exc_info=True)
        return jsonify({"error": f"Failed to process LLM analysis request. Details: {str(e)}"}), 500

@api_bp.route('/')
def home():
    return "Sirius is watching!"





# --- Depreciated Endpoints ---
"""
@api_bp.route('/ingest/<scan_type>', methods=['POST'])
def ingest_report(scan_type):
    # Access services and logger via current_app
    sast_service = current_app.sast_service
    container_service = current_app.container_service 
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
            # Add a check that the service is actually initialized
            if not sast_service:
                current_app.logger.error("SAST service not initialized in current_app.")
                return jsonify({"error": "SAST service not available."}), 500

            current_app.logger.debug(f"Calling sast_service.ingest_semgrep_report with dict keys: {report_data.keys()}")
            new_count, total_count = sast_service.ingest_semgrep_report(report_data)
            current_app.logger.info(f"Ingested {new_count} new SAST findings.")
            message = f"Successfully ingested {new_count} new SAST findings (out of {total_count} in report)."
        elif scan_type == 'container':
            # Add a check that the service is actually initialized
            if not container_service:
                current_app.logger.error("Container service not initialized in current_app.")
                return jsonify({"error": "Container service not available."}), 500

            current_app.logger.debug(f"Calling container_service.ingest_trivy_report with dict keys: {report_data.keys()}")
            new_count, total_count = container_service.ingest_trivy_report(report_data) 
            current_app.logger.info(f"Ingested {new_count} new Container findings.")
            message = f"Successfully ingested {new_count} new Container findings (out of {total_count} in report)."
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
"""
"""@api_bp.route('/findings/<scan_type>', methods=['GET'])
def get_findings(scan_type):
    # Access services via current_app
    sast_service = current_app.sast_service
    container_service = current_app.container_service 

    if scan_type == 'sast':
        # Add a check that the service is actually initialized
        if not sast_service:
            current_app.logger.error("SAST service not initialized in current_app.")
            return jsonify({"error": "SAST service not available."}), 500
        findings = sast_service.get_all_findings()
        return jsonify(findings), 200
    elif scan_type == 'container':
        # Add a check that the service is actually initialized
        if not container_service:
            current_app.logger.error("Container service not initialized in current_app.")
            return jsonify({"error": "Container service not available."}), 500
        findings = container_service.get_all_findings()
        return jsonify(findings), 200 
    else:
        return jsonify({"error": f"Retrieval for scan type '{scan_type}' not yet implemented."}), 400
"""
