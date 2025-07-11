from backend.models.container_models import ContainerScan, ContainerFinding
from backend.models import db
import logging
import json
import hashlib
from datetime import datetime

logger = logging.getLogger(__name__)

class ContainerService:

    def __init__(self, db_instance):
        self.db=db_instance

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


                
                
