# backend/models/sast_models.py
# This will contain the SQLAlchemy model definition only for SAST findings.
 


from flask_sqlalchemy import SQLAlchemy


sast_db = SQLAlchemy()

class SastFinding(sast_db.Model):
    __tablename__ = 'sast_findings' # Explicit table name

    id = sast_db.Column(sast_db.Integer, primary_key=True)
    # No 'scan_type' or 'tool' needed here, as this DB is specifically for SAST/Semgrep
    finding_id = sast_db.Column(sast_db.String(255), unique=True, nullable=False) # Unique ID for this specific finding instance
    severity = sast_db.Column(sast_db.String(20)) # e.g., 'HIGH', 'MEDIUM', 'LOW', 'WARNING', 'ERROR'
    title = sast_db.Column(sast_db.String(255), nullable=False)
    description = sast_db.Column(sast_db.Text)
    file_path = sast_db.Column(sast_db.String(255))
    line_number = sast_db.Column(sast_db.Integer)
    rule_id = sast_db.Column(sast_db.String(255)) # Original rule ID, e.g., check_id from Semgrep
    code_snippet = sast_db.Column(sast_db.Text) # The vulnerable line(s) of code
    suggested_fix = sast_db.Column(sast_db.Text) # Suggested fix from the tool
    # No CVE, package_name, version, cvss_score as they are not for SAST

    def __repr__(self):
        return f"SastFinding('{self.title}', '{self.severity}', '{self.file_path}:{self.line_number}')"

    def to_dict(self):
        return {
            'id': self.id,
            'finding_id': self.finding_id,
            'severity': self.severity,
            'title': self.title,
            'description': self.description,
            'file_path': self.file_path,
            'line_number': self.line_number,
            'rule_id': self.rule_id,
            'code_snippet': self.code_snippet,
            'suggested_fix': self.suggested_fix
        }