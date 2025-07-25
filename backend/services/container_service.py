# backend/services/container_service.py

import logging
from datetime import datetime, timedelta
from hashlib import sha256
from typing import Dict, Any, Tuple

from backend.models.container_models import ContainerFinding # Assuming this path

logger = logging.getLogger(__name__)

class ContainerService:
    def __init__(self, db_instance, llm_service=None):
        self.db = db_instance # This is your Flask-SQLAlchemy 'db' instance
        self.llm_service = llm_service
        self.cache_expiration_days = 7 # Example: Cache LLM analysis for 7 days

    def get_or_generate_llm_analysis_for_finding(self, finding_id: int) -> Tuple[Dict[str, Any], int]:
        """
        Retrieves or generates LLM analysis for a given container finding, with caching.
        """
        # Access the session directly via self.db.session
        finding = self.db.session.query(ContainerFinding).filter_by(id=finding_id).first()
        if not finding:
            return {"error": f"Container Finding with ID {finding_id} not found."}, 404

        if not self.llm_service or not self.llm_service.is_loaded():
            logger.error(f"LLM service not available for container finding {finding_id}. Cannot generate analysis.")
            return {"error": "LLM service is not available. Please check server logs."}, 503

        # Generate prompt and its hash for cache comparison
        current_prompt = self.llm_service.generate_prompt("container", finding.to_dict())
        current_prompt_hash = sha256(current_prompt.encode('utf-8')).hexdigest()

        # Check cache validity
        cache_expired = True
        if finding.llm_analysis_timestamp and finding.llm_analysis_status == 'completed':
            cache_expired_time = datetime.utcnow() - timedelta(days=self.cache_expiration_days)
            if (finding.llm_analysis_timestamp > cache_expired_time and
                finding.llm_analysis_prompt_hash == current_prompt_hash):
                cache_expired = False
                logger.info(f"LLM analysis for container finding ID {finding_id} is cached and valid.")
                return {
                    "finding_id": finding.id,
                    "summary": finding.llm_analysis_summary,
                    "recommendations": finding.llm_analysis_recommendations,
                    "risk_score": finding.llm_analysis_risk_score,
                    "status": finding.llm_analysis_status,
                    "cached": True
                }, 200

        # If cache is expired or not present, generate new analysis
        logger.info(f"LLM analysis for container finding ID {finding_id} not cached or prompt mismatch. Generating new analysis.")
        
        # Set status to pending before calling LLM
        finding.llm_analysis_status = "pending"
        self.db.session.add(finding)
        self.db.session.commit() # Commit the pending status immediately

        try:
            llm_analysis_data = self.llm_service.generate_analysis(current_prompt)
            
            # Update finding with new analysis data
            finding.llm_analysis_summary = llm_analysis_data.get('summary')
            finding.llm_analysis_recommendations = llm_analysis_data.get('recommendations')
            finding.llm_analysis_risk_score = llm_analysis_data.get('risk_score')
            finding.llm_analysis_timestamp = datetime.utcnow()
            finding.llm_analysis_prompt_hash = current_prompt_hash
            finding.llm_analysis_status = "completed"
            
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
            logger.error(f"Failed to generate or save LLM analysis for container finding ID {finding_id}: {e}", exc_info=True)
            # Set status to failed if an error occurs
            finding.llm_analysis_status = "failed"
            finding.llm_analysis_timestamp = datetime.utcnow()
            self.db.session.add(finding)
            self.db.session.commit() # Commit failed status
            return {"error": f"Failed to generate LLM analysis for container finding: {e}"}, 500

    def ingest_trivy_report(self, report_data: Dict[str, Any]) -> Tuple[int, int]:
        new_findings_count = 0

        if report_data is None:
            logger.error("ingest_trivy_report received None for report_data.")
            return 0, 0
        if not isinstance(report_data, dict):
            logger.error(f"ingest_trivy_report received non-dict report_data: {type(report_data)}")
            return 0, 0

        results = report_data.get('Results', [])
        total_findings_in_report = sum(len(result.get('Vulnerabilities', [])) for result in results)

        if not results:
            logger.info("No 'Results' list found or it's empty in the Trivy report.")
            return 0, 0

        for result in results:
            vulnerabilities = result.get('Vulnerabilities', [])
            for vuln in vulnerabilities:
                try:
                    vulnerability_id = vuln.get('VulnerabilityID')
                    pkg_name = vuln.get('PkgName')
                    installed_version = vuln.get('InstalledVersion')
                    fixed_version = vuln.get('FixedVersion', 'None Available')
                    severity = vuln.get('Severity', 'UNKNOWN').upper()
                    title = vuln.get('Title', 'No title provided by scanner.')
                    description = vuln.get('Description', 'No description provided by scanner.')
                    primary_url = vuln.get('PrimaryURL', 'N/A')

                    # CVSS metrics
                    cvss_v3_score = None
                    cvss_v3_vector = None
                    cvss_v2_score = None
                    cvss_v2_vector = None
                    
                    if 'CVSS' in vuln:
                        nvd = vuln['CVSS'].get('nvd', {})
                        if 'V3Score' in nvd:
                            cvss_v3_score = nvd['V3Score']
                        if 'V3Vector' in nvd:
                            cvss_v3_vector = nvd['V3Vector']
                        if 'V2Score' in nvd:
                            cvss_v2_score = nvd['V2Score']
                        if 'V2Vector' in nvd:
                            cvss_v2_vector = nvd['V2Vector']

                    published_date = vuln.get('PublishedDate')
                    last_modified_date = vuln.get('LastModifiedDate')

                    unique_finding_key = sha256(f"{vulnerability_id}-{pkg_name}-{installed_version}".encode('utf-8')).hexdigest()

                    existing_finding = self.db.session.query(ContainerFinding).filter_by(unique_finding_key=unique_finding_key).first()

                    if not existing_finding:
                        new_finding = ContainerFinding(
                            unique_finding_key=unique_finding_key,
                            vulnerability_id=vulnerability_id,
                            pkg_name=pkg_name,
                            installed_version=installed_version,
                            fixed_version=fixed_version,
                            severity=severity,
                            title=title,
                            description=description,
                            primary_url=primary_url,
                            cvss_nvd_v3_score=cvss_v3_score,
                            cvss_nvd_v3_vector=cvss_v3_vector,
                            cvss_nvd_v2_score=cvss_v2_score,
                            cvss_nvd_v2_vector=cvss_v2_vector,
                            published_date=datetime.fromisoformat(published_date.replace('Z', '+00:00')) if published_date else None,
                            last_modified_date=datetime.fromisoformat(last_modified_date.replace('Z', '+00:00')) if last_modified_date else None
                        )
                        self.db.session.add(new_finding)
                        new_findings_count += 1
                        logger.debug(f"Adding new container finding: {unique_finding_key}")
                    else:
                        logger.debug(f"Skipping duplicate container finding: {unique_finding_key}")

                except Exception as e:
                    logger.error(f"Error processing container vulnerability: {e}", exc_info=True)
                    continue

        try:
            self.db.session.commit()
            logger.info(f"Successfully committed {new_findings_count} new container findings.")
        except Exception as e:
            self.db.session.rollback()
            logger.error(f"Failed to commit container findings to DB: {e}", exc_info=True)
            return 0, total_findings_in_report

        return new_findings_count, total_findings_in_report

    def get_all_findings(self):
        findings = self.db.session.query(ContainerFinding).all()
        return [f.to_dict() for f in findings]