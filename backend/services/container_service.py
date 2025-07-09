from backend.models.container_models import ContainerScan, ContainerFinding
from backend.models import db
import logging
import json
import hashlib

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
            artifact_name=artifact_name,
            image_digest=image_digest,
            os_family=os_family,
            os_name=os_name
            report_hash=report_hash,
            scan_timestamp=report_data.get('CreatedAt', None)
        )

        self.db.session.add(new_scan)
        self.db.session.flush() #Flush to get the new scan ID for findings

        logger.info(f"New container scan record created for image '{artifact_name}' (ID: {new_scan.id}).")

        # Process findings
