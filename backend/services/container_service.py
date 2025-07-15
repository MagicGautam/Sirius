from backend.models.container_models import ContainerScan, ContainerFinding
from backend.models import db
import logging
import json
import hashlib
from datetime import datetime
from backend.services.llm_service import LLMService 

logger = logging.getLogger(__name__)

class ContainerService:

    def __init__(self, db_instance, llm_service: LLMService= None):
        self.db=db_instance
        self.llm_service=llm_service
        if not self.llm_service:
            # Initialize with default if not provided (e.g., for testing or if Flask app handles init)
            logger.warning("LLMService not provided to ContainerService. Initializing default.")
            self.llm_service = LLMService() # This will attempt connection to Ollama immediately


    def ingest_trivy_report(self, report_data):
        
        
        if report_data is None:
            logger.error("ingest_trivy_report received None for report_data.")
            return 0, 0
        if not isinstance(report_data, dict):
            logger.error(f"ingest_trivy_report received non-dict report_data: {type(report_data)} - {report_data}")
            return 0, 0
        
        total_findings_in_report = 0
        newly_ingested_findings = 0

        #Generating the hash for the entire report data for deduplication
        report_json_string = json.dumps(report_data, sort_keys=True)
        report_hash = hashlib.sha256(report_json_string.encode('utf-8')).hexdigest()
        logger.debug(f"Generated report hash: {report_hash}")

        existing_scan = self.db.session.query(ContainerScan).filter_by(report_hash=report_hash).first()

        if existing_scan:
            logger.info(f"Report with hash {report_hash} already exists. Skipping ingestion.")
            # Optionally, you could update existing_scan.scan_timestamp here if you want to mark it as "recently seen"
            # existing_scan.scan_timestamp = datetime.utcnow()
            # self.db.session.add(existing_scan)
            # self.db.session.commit()
            return 0, 0
        
        # Extracting metadata from the report
        artifact_name = report_data.get('ArtifactName', 'unknown_image')
        metadata = report_data.get('Metadata', {})
        image_digest = metadata.get('ImageID', report_data.get('ImageID')) # Fallback for older Trivy or other report types
        os_info = metadata.get('OS', {})
        os_family = os_info.get('Family')
        os_name = os_info.get('Name')

        new_scan = ContainerScan(
            report_hash=report_hash,
            image_name=artifact_name,
            image_digest=image_digest,
            os_family=os_family,
            os_name=os_name,
            scan_timestamp=report_data.get('CreatedAt', None)
        )

        self.db.session.add(new_scan)
        self.db.session.flush() #Flush to get the new scan ID for findings

        logger.info(f"New container scan record created for image '{artifact_name}' (ID: {new_scan.id}).")

        # Process findings

        results= report_data.get('Results', [])
        for result in results:
            target = result.get('Target') # Target is the file or directory where the vulnerability was found
            vulnerabilities = result.get('Vulnerabilities', []) # List of vulnerabilities found in the target
            total_findings_in_report += len(vulnerabilities)

            for vulnerability in vulnerabilities:
                finding_id = vulnerability.get('VulnerabilityID')
                if not finding_id:
                    logger.warning(f"Skipping finding with no VulnerabilityID in target '{target}'.")
                    continue
                
                # Check if this finding already exists
                existing_finding = self.db.session.query(ContainerFinding).filter_by(
                    scan_id=new_scan.id,
                    vulnerability_id=finding_id
                ).first()

                if existing_finding:
                    logger.debug(f"Finding {finding_id} already exists for scan ID {new_scan.id}. Skipping ingestion.")
                    continue

                vulnerability_id = vulnerability.get('VulnerabilityID')
                pkg_name = vulnerability.get('PkgName')
                installed_version = vulnerability.get('InstalledVersion')
                fixed_version = vulnerability.get('FixedVersion')
                severity = vulnerability.get('Severity')
                title = vulnerability.get('Title')
                description = vulnerability.get('Description')
                primary_url = vulnerability.get('PrimaryURL')
                published_date_str = vulnerability.get('PublishedDate')
                last_modified_date_str = vulnerability.get('LastModifiedDate')
                
                published_date = datetime.fromisoformat(published_date_str.replace('Z', '+00:00')) if published_date_str else None
                last_modified_date = datetime.fromisoformat(last_modified_date_str.replace('Z', '+00:00')) if last_modified_date_str else None

                cvss_nvd_v2_vector = None
                cvss_nvd_v2_score = None
                cvss_nvd_v3_vector = None
                cvss_nvd_v3_score = None

                cvss_metrics = vulnerability.get('CVSS', [])
                if not isinstance(cvss_metrics, list): # If CVSS is not a list, it's malformed or single dict
                    logger.warning(f"CVSS metrics for {finding_id} is not a list, type: {type(cvss_metrics)}. Attempting to treat as single item.")
                    if isinstance(cvss_metrics, dict):
                        cvss_metrics = [cvss_metrics] # Wrap single dict in list
                    else:
                        cvss_metrics = [] # If it's a string or other, just empty it
                
                for cvss in cvss_metrics:
                    if not isinstance(cvss, dict): # <--- **THE MAIN FIX**
                        logger.warning(f"Skipping non-dict item in 'CVSS' list for {finding_id}: {type(cvss)} - {cvss}")
                        continue # Skip to the next item if it's not a dictionary

                    if cvss.get('V2Vector'):
                        cvss_nvd_v2_vector = cvss.get('V2Vector')
                        cvss_nvd_v2_score = cvss.get('V2Score')
                    if cvss.get('V3Vector'):
                        cvss_nvd_v3_vector = cvss.get('V3Vector')
                        cvss_nvd_v3_score = cvss.get('V3Score')

                # Create a unique key for the finding within the scan to prevent exact duplicates per scan
                # This unique key is for in-report deduplication if Trivy somehow sends the same vuln twice in one report
                # The DB unique constraint (`_trivy_finding_uc`) handles across-report deduplication for findings.
                unique_finding_key_components = [
                    vulnerability_id, pkg_name, installed_version, new_scan.id
                ]
                unique_finding_key = hashlib.sha256(json.dumps(unique_finding_key_components, sort_keys=True).encode('utf-8')).hexdigest()


                # Create a new finding
                new_finding = ContainerFinding(
                    scan_id=new_scan.id,
                    vulnerability_id=vulnerability_id,
                    pkg_name=pkg_name,
                    installed_version=installed_version,
                    fixed_version=fixed_version,
                    severity=severity,
                    title=title,
                    description=description,
                    primary_url=primary_url,
                    cvss_nvd_v2_vector=cvss_nvd_v2_vector,
                    cvss_nvd_v2_score=cvss_nvd_v2_score,
                    cvss_nvd_v3_vector=cvss_nvd_v3_vector,
                    cvss_nvd_v3_score=cvss_nvd_v3_score,
                    published_date=published_date,
                    last_modified_date=last_modified_date,
                    unique_finding_key=unique_finding_key
                )
                self.db.session.add(new_finding)
                newly_ingested_findings += 1    

        new_scan.total_vulnerabilities_found = newly_ingested_findings
        self.db.session.add(new_scan) # Re-add to ensure total_vulnerabilities_found update is tracked
        
        self.db.session.commit()
        logger.info(f"Ingested {newly_ingested_findings} new container findings for scan ID {new_scan.id}.")

        return newly_ingested_findings, total_findings_in_report


    def get_all_findings(self):
        """Retrieve all container findings."""

        findings = self.db.session.query(ContainerFinding).all()
        return [f.to_dict()  for f in findings]

    def get_findings_by_scan_id(self, scan_id): 
        """Retrieve all findings for a specific scan ID."""
        
        findings = self.db.session.query(ContainerFinding).filter_by(scan_id=scan_id).all()
        return [f.to_dict() for f in findings]

    def get_scan_by_id(self, scan_id: int):
            """Retrieves a specific container scan by ID."""
            scan = self.db.session.get(ContainerScan, scan_id)
            return scan.to_dict() if scan else None

    def get_findings_for_scan(self, scan_id: int):
            """Retrieves all findings for a specific container scan."""
            findings = self.db.session.query(ContainerFinding).filter_by(scan_id=scan_id).all()
            return [f.to_dict() for f in findings] if findings else []   
    
    
    def get_or_generate_llm_analysis_for_finding(self, finding_id: int):
        """
        Retrieves cached LLM analysis for a finding or generates a new one if not
        cached, expired, or prompt has changed.
        """
        logger.info(f"Received request to analyze container finding ID: {finding_id} with LLM via Ollama.")

        finding = self.db.session.get(ContainerFinding, finding_id) # Use .get for primary key lookup
        if not finding:
            logger.warning(f"Container finding with ID {finding_id} not found.")
            return None, 404 # Return None and a 404 status

        # Generate the current prompt based on the finding's data
        current_prompt = self.llm_service.generate_prompt("container", finding.to_dict())
        current_prompt_hash = hashlib.sha256(current_prompt.encode('utf-8')).hexdigest()

        # Cache Invalidation Logic
        # Define cache expiration (e.g., 7 days)
        cache_expiration_days = 7
        cache_expired_time = datetime.utcnow() - timedelta(days=cache_expiration_days)

        # Check if cache is valid
        is_cached_and_valid = (
            finding.llm_analysis_status == 'completed' and
            finding.llm_analysis_timestamp and
            finding.llm_analysis_timestamp > cache_expired_time and
            finding.llm_analysis_prompt_hash == current_prompt_hash
        )

        if is_cached_and_valid:
            logger.info(f"LLM analysis for finding ID {finding_id} found in cache and is valid.")
            return {
                "id": finding.id,
                "llm_analysis_summary": finding.llm_analysis_summary,
                "llm_analysis_recommendations": finding.llm_analysis_recommendations,
                "llm_analysis_risk_score": finding.llm_analysis_risk_score,
                "llm_analysis_timestamp": finding.llm_analysis_timestamp.isoformat(),
                "llm_analysis_status": finding.llm_analysis_status
            }, 200 # Return cached data and 200 status
        else:
            logger.info(f"LLM analysis for finding ID {finding_id} not cached or prompt mismatch. Generating new analysis.")
            if not self.llm_service.is_loaded():
                logger.error("LLM service is not loaded. Cannot generate analysis.")
                # You might want to update status to 'failed' if this happens frequently
                return {"message": "LLM service is not available. Please check Ollama server."}, 503

            # Update status to pending before generation
            finding.llm_analysis_status = 'pending'
            self.db.session.add(finding)
            self.db.session.commit() # Commit to save pending status

            try:
                llm_analysis_data = self.llm_service.generate_analysis(current_prompt)

                finding.llm_analysis_summary = llm_analysis_data.get('summary')
                finding.llm_analysis_recommendations = llm_analysis_data.get('recommendations')
                finding.llm_analysis_risk_score = llm_analysis_data.get('risk_score') # Will be None for now
                finding.llm_analysis_timestamp = datetime.utcnow()
                finding.llm_analysis_status = 'completed'
                finding.llm_analysis_prompt_hash = current_prompt_hash # Save the hash of the prompt that generated this analysis

                self.db.session.add(finding)
                self.db.session.commit()
                logger.info(f"LLM analysis for finding ID {finding_id} successfully generated and saved to DB.")

                return {
                    "id": finding.id,
                    "llm_analysis_summary": finding.llm_analysis_summary,
                    "llm_analysis_recommendations": finding.llm_analysis_recommendations,
                    "llm_analysis_risk_score": finding.llm_analysis_risk_score,
                    "llm_analysis_timestamp": finding.llm_analysis_timestamp.isoformat(),
                    "llm_analysis_status": finding.llm_analysis_status
                }, 200

            except Exception as e:
                self.db.session.rollback() # Rollback in case of error
                finding.llm_analysis_status = 'failed'
                self.db.session.add(finding)
                self.db.session.commit()
                logger.error(f"Failed to generate or save LLM analysis for finding ID {finding_id}: {e}", exc_info=True)
                return {"message": f"Error generating LLM analysis: {e}"}, 500

                
                
