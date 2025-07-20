# backend/services/sast_service.py

import logging
from datetime import datetime, timedelta
from hashlib import sha256
from typing import Dict, Any, Tuple

# Make sure SastFinding is imported from your models
from backend.models.sast_models import SastFinding # Assuming this is the correct path and structure for SastFinding
# NOTE: If you decide to add a SastScan model later, you would import it here too.

logger = logging.getLogger(__name__)

class SastService:
    def __init__(self, db_instance, llm_service=None):
        self.db = db_instance # This is your Flask-SQLAlchemy 'db' instance (or a SQLAlchemy session manager)
        self.llm_service = llm_service
        self.cache_expiration_days = 7

    def get_or_generate_llm_analysis_for_finding(self, finding_id: int) -> Tuple[Dict[str, Any], int]:
        """
        Retrieves or generates LLM analysis for a given SAST finding, with caching.
        """
        # Access the session directly via self.db.session when using Flask-SQLAlchemy's db.Model
        # Since SastFinding now uses `declarative_base()`, `self.db.session` is indeed the correct way to query.
        
        finding = self.db.session.query(SastFinding).filter_by(id=finding_id).first()
        if not finding:
            return {"error": f"SAST Finding with ID {finding_id} not found."}, 404

        if not self.llm_service or not self.llm_service.is_loaded():
            logger.error(f"LLM service not available for SAST finding {finding_id}. Cannot generate analysis.")
            return {"error": "LLM service is not available. Please check server logs."}, 503

        # Ensure we're using the correct finding attributes for the prompt
        # The .to_dict() method should reflect the current model structure
        finding_data_for_prompt = {
            "rule_id": finding.rule_id,
            "severity": finding.severity,
            "file_path": finding.file_path,
            "line_number": finding.line_number,
            "description": finding.description,
            "code_snippet": finding.code_snippet,
            "scanner_suggested_fix": finding.scanner_suggested_fix
        }
        current_prompt = self.llm_service.generate_prompt("sast", finding_data_for_prompt)
        current_prompt_hash = sha256(current_prompt.encode('utf-8')).hexdigest()

        cache_expired = True
        # Check LLM analysis status and prompt hash for cache validity
        if finding.llm_analysis_timestamp and finding.llm_analysis_status == 'completed':
            cache_expired_time = datetime.utcnow() - timedelta(days=self.cache_expiration_days)
            if (finding.llm_analysis_timestamp > cache_expired_time and
                finding.llm_analysis_prompt_hash == current_prompt_hash):
                cache_expired = False
                logger.info(f"LLM analysis for SAST finding ID {finding_id} is cached and valid.")
                return {
                    "finding_id": finding.id,
                    "summary": finding.llm_analysis_summary,
                    "recommendations": finding.llm_analysis_recommendations,
                    "risk_score": finding.llm_analysis_risk_score,
                    "status": finding.llm_analysis_status,
                    "cached": True
                }, 200

        logger.info(f"LLM analysis for SAST finding ID {finding_id} not cached or prompt mismatch. Generating new analysis.")
        
        # Update status before starting analysis
        finding.llm_analysis_status = "pending"
        # Optional: Set timestamp/hash to signal work in progress, but final data overwrites
        finding.llm_analysis_timestamp = datetime.utcnow()
        finding.llm_analysis_prompt_hash = current_prompt_hash # Store the prompt hash even for pending
        self.db.session.add(finding)
        self.db.session.commit() # Commit the pending status immediately

        try:
            llm_analysis_data = self.llm_service.generate_analysis(current_prompt)
            
            # Assign results from LLM service to the correct model fields
            finding.llm_analysis_summary = llm_analysis_data.get('summary')
            finding.llm_analysis_recommendations = llm_analysis_data.get('recommendations')
            finding.llm_analysis_risk_score = llm_analysis_data.get('risk_score')
            finding.llm_analysis_timestamp = datetime.utcnow() # Update timestamp on completion
            finding.llm_analysis_status = "completed"
            # prompt_hash already set when status was pending, if needed again:
            # finding.llm_analysis_prompt_hash = current_prompt_hash 
            
            self.db.session.add(finding)
            self.db.session.commit() # Commit completed status and new data

            return {
                "finding_id": finding.id,
                "summary": finding.llm_analysis_summary,
                "recommendations": finding.llm_analysis_recommendations,
                "risk_score": finding.llm_analysis_risk_score,
                "status": finding.llm_analysis_status,
                "cached": False
            }, 200

        except Exception as e:
            logger.error(f"Failed to generate or save LLM analysis for SAST finding ID {finding_id}: {e}", exc_info=True)
            finding.llm_analysis_status = "failed"
            finding.llm_analysis_timestamp = datetime.utcnow() # Update timestamp on failure
            self.db.session.add(finding)
            self.db.session.commit() # Commit failed status
            return {"error": f"Failed to generate LLM analysis for SAST finding: {e}"}, 500

    def ingest_semgrep_report(self, report_data: Dict[str, Any]) -> Tuple[int, int]:
        new_findings_count = 0
        
        if report_data is None:
            logger.error("ingest_semgrep_report received None for report_data.")
            return 0, 0
        if not isinstance(report_data, dict):
            logger.error(f"ingest_semgrep_report received non-dict report_data: {type(report_data)} - {report_data}")
            return 0, 0

        logger.debug(f"Received report_data keys: {report_data.keys()}")
        
        results = report_data.get('results', [])
        total_findings_in_report = len(results)

        if not results:
            logger.info("No 'results' list found or it's empty in the SAST report.")
            return 0, 0

        # --- IMPORTANT: We should ideally create a SastScan record here
        # Similar to ContainerScan, to properly track scan runs and link findings.
        # For now, keeping `scan_id=0` as it's nullable, but this is a future improvement.
        # If you were to add `SastScan` model, you'd add similar logic here:
        # 1. Parse scan-level metadata (e.g., source repo, commit hash, scan time from report)
        # 2. Create `new_sast_scan = SastScan(...)`
        # 3. `self.db.session.add(new_sast_scan)`
        # 4. `self.db.session.flush()` to get `new_sast_scan.id`
        # 5. Use `scan_id_for_findings = new_sast_scan.id`
        # 6. Finally, update `new_sast_scan.total_findings = new_findings_count` and commit.
        # For now, we'll keep `scan_id=0` as `nullable=True` allows it.
        sast_scan_id = 0 # Placeholder: For a real system, generate a scan record and use its ID.


        for result in results:
            if not isinstance(result, dict):
                logger.warning(f"Skipping non-dictionary item found in 'results' list: {result}")
                continue

            try:
                check_id = result.get('check_id')
                file_path = result.get('path')
                line_number = result.get('start', {}).get('line')
                extra = result.get('extra', {})
                severity = extra.get('severity', 'UNKNOWN').upper()
                message = extra.get('message', 'No description provided')
                code_snippet = extra.get('lines')
                
                # IMPORTANT: Use 'scanner_suggested_fix' as per the new model
                scanner_suggested_fix = extra.get('fix') 

                title = check_id.split('.')[-1].replace('-',' ').title() if check_id else 'SAST Finding'
                if title == 'Cbc Padding Oracle':
                    title = "CBC Padding Oracle Vulnerability"
                
                # IMPORTANT: Calculate unique_finding_key based on your chosen model's intent
                # Including message in the hash as per your previous unique_finding_id structure.
                # Adding scan_id to the hash for uniqueness IF you have multiple scans.
                # If scan_id is always 0, it doesn't add much to uniqueness across "scans".
                # If `scan_id` becomes a foreign key to a `SastScan` record, then it's vital here.
                unique_finding_key = sha256(
                    f"{check_id}-{file_path}-{line_number}-{message}-{sast_scan_id}".encode('utf-8')
                ).hexdigest()

                # IMPORTANT: Query using the correct column name: unique_finding_key
                existing_finding = self.db.session.query(SastFinding).filter_by(unique_finding_key=unique_finding_key).first()

                if not existing_finding:
                    new_finding = SastFinding(
                        # IMPORTANT: Assign to unique_finding_key, not finding_id
                        unique_finding_key=unique_finding_key, 
                        scan_id=sast_scan_id, # Use the defined scan_id (currently 0)
                        rule_id=check_id,
                        severity=severity,
                        file_path=file_path,
                        line_number=line_number,
                        description=message,
                        code_snippet=code_snippet,
                        # IMPORTANT: Assign to scanner_suggested_fix, not suggested_fix
                        scanner_suggested_fix=scanner_suggested_fix,
                        # No need to set LLM fields here, they are nullable and will be populated later
                    )
                    self.db.session.add(new_finding)
                    new_findings_count += 1
                    logger.debug(f"Adding new SAST finding: {unique_finding_key}") 
                else:
                    logger.debug(f"Skipping duplicate SAST Finding: {unique_finding_key}")
                
            except Exception as e:
                logger.error(f"Error processing SAST finding: {e}", exc_info=True)
                # For robustness, consider adding a rollback for this specific finding if it's critical,
                # but typically for loops, you log and continue.
                continue

        # Commit changes at the end of the ingestion process
        try:
            self.db.session.commit()
            logger.info(f"Successfully committed {new_findings_count} new SAST findings.")
        except Exception as e:
            self.db.session.rollback() # Explicit rollback if commit fails
            logger.error(f"Failed to commit SAST findings to DB: {e}", exc_info=True)
            return 0, total_findings_in_report 

        return new_findings_count, total_findings_in_report
        
    def get_all_findings(self):
        # IMPORTANT: Use self.db.session.query(SastFinding)
        findings = self.db.session.query(SastFinding).all()
        return [f.to_dict() for f in findings]

    # Added for completeness, if you have a SastScan model and need to get findings for it.
    # This would require a SastScan model to exist and findings to be linked via foreign key.
    # def get_findings_by_scan_id(self, scan_id: int):
    #     findings = self.db.session.query(SastFinding).filter_by(scan_id=scan_id).all()
    #     return [f.to_dict() for f in findings]