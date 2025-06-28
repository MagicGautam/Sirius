# backend/services/sast_service.py
#File will contain the logic to parse Semgrep reports and interact with the sast_db.

from models.sast_models import SastFinding, sast_db
 

class SastService:
    def __init__(self, app=None):
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        sast_db.init_app(app)
        with app.app_context():
            sast_db.create_all()
            print("SAST database initialized and tables created/updated.")
    
    def ingest_semgrep_report(self, report_data):
        new_findings_count=0
        results=report_data.get('results', [])

        for result in results:
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
                    sast_db.session.add(new_finding)
                    new_findings_count += 1

                else:
                    print(f"Skipping duplicate SAST Finding: {unique_finding_id}")
            
            except Exception as e:
                print(f"Error processing SAST finding: {e}")
                continue

            sast_db.session.commit()
            return new_findings_count, len(results)
        
    def get_all_findings(self):
        findings= SastFinding.query.all()
        return [f.to_dict() for f in findings]
