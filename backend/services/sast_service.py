# backend/services/sast_service.py

import logging
from datetime import datetime, timedelta
import hashlib
import json
from typing import Dict, Any, Tuple
from sqlalchemy.exc import IntegrityError
from hashlib import sha256
# Make sure SastFinding is imported from your models
from backend.models.sast_models import SastFinding, SastScan 

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
        finding = self.db.session.query(SastFinding).filter_by(id=finding_id).first()
        if not finding:
            return {"error": f"SAST Finding with ID {finding_id} not found."}, 404

        if not self.llm_service or not self.llm_service.is_loaded():
            logger.error(f"LLM service not available for SAST finding {finding_id}. Cannot generate analysis.")
            return {"error": "LLM service is not available. Please check server logs."}, 503

        finding_data_for_prompt = finding.to_dict()
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

    def ingest_sast_report(self, report_data: Dict[str, Any], project_name: str) -> Tuple[int, int]:
        """
        Ingests a full SAST report.
        Creates a new SastScan entry and then calls the finding ingestion logic.
        Returns the count of new findings created and the total findings in the report.
        """
        if not report_data or not project_name:
            logger.error("ingest_sast_report received None or empty data.")
            return 0, 0
        if not isinstance(report_data, dict):
            logger.error(f"ingest_sast_report received non-dict report_data: {type(report_data)}")
            return 0, 0

        # Create a unique hash of the entire report to check for duplicates
        report_hash = hashlib.sha256(json.dumps(report_data, sort_keys=True).encode('utf-8')).hexdigest()

        existing_scan = self.db.session.query(SastScan).filter_by(report_hash=report_hash).first()
        if existing_scan:
            logger.info(f"SAST report with hash {report_hash} already exists. Skipping ingestion.")
            total_findings = len(report_data.get('results', []))
            return 0, total_findings

        # Extract metadata for the new SastScan entry. We'll use project_name from the API call.
        scan = SastScan(
            project_name=project_name,
            report_hash=report_hash
        )

        try:
            self.db.session.add(scan)
            self.db.session.commit()
            logger.info(f"Created new SastScan entry with ID: {scan.id}")
            scan_id = scan.id
        except IntegrityError as e:
            self.db.session.rollback()
            logger.error(f"Failed to create SastScan due to IntegrityError: {e}", exc_info=True)
            return 0, 0
        except Exception as e:
            self.db.session.rollback()
            logger.error(f"Failed to create SastScan: {e}", exc_info=True)
            return 0, 0

        # Now, call the new modular method to ingest the findings
        new_findings_count, total_findings_in_report = self._ingest_sast_findings(report_data, scan_id)

        # Update the parent scan with the total count and commit
        scan.total_vulnerabilities_found = total_findings_in_report
        self.db.session.add(scan)
        self.db.session.commit()

        return new_findings_count, total_findings_in_report
    
    def _ingest_sast_findings(self, report_data: Dict[str, Any], scan_id: int) -> Tuple[int, int]:
        
        new_findings_count = 0
        results = report_data.get('results', [])
        total_findings_in_report = len(results)

        if report_data is None:
            logger.error("ingest_semgrep_report received None for report_data.")
            return 0, 0
        if not isinstance(report_data, dict):
            logger.error(f"ingest_semgrep_report received non-dict report_data: {type(report_data)} - {report_data}")
            return 0, 0

        logger.debug(f"Received rep ort_data keys: {report_data.keys()}")
        
        
        if not results:
            logger.info("No 'results' list found or it's empty in the SAST report.")
            return 0, 0

        for result in results:
            if not isinstance(result, dict):
                logger.warning(f"Skipping non-dictionary item found in 'results' lists for scan {scan_id}: {result}")
                continue

            try:
                check_id = result.get('check_id')
                file_path = result.get('path')
                line_number = result.get('start', {}).get('line')
                extra = result.get('extra', {})
                severity = extra.get('severity', 'UNKNOWN').upper()
                message = extra.get('message', 'No description provided')
                code_snippet = extra.get('lines')
                scanner_suggested_fix = extra.get('fix') 

                """title = check_id.split('.')[-1].replace('-',' ').title() if check_id else 'SAST Finding'
                if title == 'Cbc Padding Oracle':
                    title = "CBC Padding Oracle Vulnerability"
                
                unique_finding_key = sha256(
                    f"{check_id}-{file_path}-{line_number}-{message}-{sast_scan_id}".encode('utf-8')
                ).hexdigest()"""

                existing_finding = self.db.session.query(SastFinding).filter_by(
                    scan_id=scan_id,
                    rule_id=check_id,
                    file_path=file_path,
                    line_number=line_number
                ).first()

                if not existing_finding:
                    new_finding = SastFinding(
                        scan_id=scan_id, 
                        rule_id=check_id,
                        severity=severity,
                        file_path=file_path,
                        line_number=line_number,
                        description=message,
                        code_snippet=code_snippet,
                        scanner_suggested_fix=scanner_suggested_fix,
                    )
                    self.db.session.add(new_finding)
                    new_findings_count += 1
                    logger.debug(f"Adding new SAST finding for Scan ID {scan_id}: {check_id}") 
                else:
                    logger.debug(f"Skipping duplicate SAST Finding within Scan ID {scan_id}: {check_id}")
                
            except Exception as e:
                logger.error(f"Error processing SAST finding for Scan {scan_id}: {e}", exc_info=True)
                continue

        try:
            self.db.session.commit()
            logger.info(f"Successfully committed {new_findings_count} new SAST findings.")
        except Exception as e:
            self.db.session.rollback() 
            logger.error(f"Failed to commit SAST findings to DB: {e}", exc_info=True)
            return 0, total_findings_in_report 

        return new_findings_count, total_findings_in_report
        
    def get_all_findings(self):
        findings = self.db.session.query(SastFinding).all()
        return [f.to_dict() for f in findings]
    
    def get_findings_for_scan(self,scan_id: int):
        scan = self.db.session.query(SastScan).filter_by(id=scan_id).first()
        if not scan:
            logger.warning(f"Attempted to fetch findings for non-existent scan ID: {scan_id}")
            return None

        findings = self.db.session.query(SastFinding).filter_by(scan_id=scan_id).all()
        return [f.to_dict() for f in findings]
    
    def get_scan_by_id(self, scan_id: int):
        scan= self.db.session.query(SastScan).filter_by(id=scan_id).first()
        if not scan:
            return None
        return scan.to_dict()

    def get_all_scans(self):
        scans = self.db.session.query(SastScan).all()
        return [s.to_dict() for s in scans]
    
    def get_findings_by_id(self, finding_id: int):
        finding = self.db.session.query(SastFinding).filter_by(id=finding_id).first()
        if not finding:
            return None
        return finding.to_dict()


    