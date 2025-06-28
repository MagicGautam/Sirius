# backend/services/sast_service.py
#File will contain the logic to parse Semgrep reports and interact with the sast_db.

from backend.models.sast_models import SastFinding
from backend.extensions import db
import logging

logger = logging.getLogger(__name__)
 

class SastService:
     # Accept the central db instance when initializing the service
    def __init__(self, db_instance):
        self.db= db_instance # Store the db instance for use in methods
    
    # DB Initialization is centeralized, so we don't need to do it here.
    
    def ingest_semgrep_report(self, report_data):
        new_findings_count=0

         # --- ADD THESE DEBUG LINES ---
        if report_data is None:
            logger.error("ingest_semgrep_report received None for report_data.")
            return 0, 0 # Or raise an appropriate error
        if not isinstance(report_data, dict):
            logger.error(f"ingest_semgrep_report received non-dict report_data: {type(report_data)} - {report_data}")
            return 0, 0

        logger.debug(f"Received report_data keys: {report_data.keys()}")
        # --- END DEBUG LINES ---
        
        
        
        results=report_data.get('results', [])

        if not results: # Add a check for empty/missing results list
            logger.info("No 'results' list found or it's empty in the SAST report.")
            return 0, 0

        for result in results:
            # --- ADD THIS CHECK ---
            if not isinstance(result, dict):
                logger.warning(f"Skipping non-dictionary item found in 'results' list: {result}")
                continue
            # --- END CHECK ---

            try:
                check_id=result.get('check_id')
                file_path=result.get('path')
                line_number=result.get('start', {}).get('line')
                extra=result.get('extra', {})
                severity=extra.get('severity', 'UNKNOWN').upper()
                message=extra.get('message', 'No description provided')
                code_snippet=extra.get('lines')
                suggested_fix=extra.get('fix')

                title= check_id.split('.')[-1].replace('-',' ').title() if check_id else 'SAST Finding'
                if title == 'Cbc Padding Oracle':
                    title= "CBC Padding Oracle Vulnerability"
                

                unique_finding_id = f"{check_id}-{file_path}-{line_number}"

                existing_finding= SastFinding.query.filter_by(finding_id=unique_finding_id).first()


                if not existing_finding:
                    new_finding = SastFinding(
                        finding_id=unique_finding_id,
                        severity=severity.upper(),
                        title=title,
                        description=message,
                        file_path=file_path,
                        line_number=line_number,
                        rule_id=check_id,
                        code_snippet=code_snippet,
                        suggested_fix=suggested_fix
                    )
                    self.db.session.add(new_finding)
                    new_findings_count += 1

                else:
                    print(f"Skipping duplicate SAST Finding: {unique_finding_id}")
            
            except Exception as e:
                print(f"Error processing SAST finding: {e}")
                continue

            self.db.session.commit()
            return new_findings_count, len(results)
        
    def get_all_findings(self):
        findings= SastFinding.query.all()
        return [f.to_dict() for f in findings]