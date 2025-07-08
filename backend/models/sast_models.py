# backend/models/sast_models.py
# This will contain the SQLAlchemy model definition only for SAST findings.

from backend.models import db
from datetime import datetime

class SastFinding(db.Model):
    __tablename__ = 'sast_findings' # Explicit table name
    __bind_key__ = 'sast_db' # Bind this model to the SAST database

    id = db.Column(db.Integer, primary_key=True)
    # No 'scan_type' or 'tool' needed here, as this DB is specifically for SAST/Semgrep
    finding_id = db.Column(db.String(255), unique=True, nullable=False) # Unique ID for this specific finding instance
    severity = db.Column(db.String(20)) # e.g., 'HIGH', 'MEDIUM', 'LOW', 'WARNING', 'ERROR'
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    file_path = db.Column(db.String(255))
    line_number = db.Column(db.Integer)
    rule_id = db.Column(db.String(255)) # Original rule ID, e.g., check_id from Semgrep
    code_snippet = db.Column(db.Text) # The vulnerable line(s) of code
    suggested_fix = db.Column(db.Text) # Suggested fix from the tool
    ingested_at = db.Column(db.DateTime, default=datetime.utcnow)
    # Adding a unique constraint on these columns to prevent exact duplicates
    __table_args__ = (db.UniqueConstraint('rule_id', 'file_path', 'line_number', 'description', name='_unique_sast_finding_constraint'),)

    llm_analysis_content = db.Column(db.Text, nullable= True) # LLM-generated analysis or remediation advice
    llm_analysis_prompt_hash = db.Column(db.String(64), unique=True, nullable=True) # Hash of the prompt used for LLM analysis
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
            'suggested_fix': self.suggested_fix,
            'ingested_at': self.ingested_at.isoformat() if self.ingested_at else None,
            'llm_analysis_content': self.llm_analysis_content,
            'llm_analysis_prompt_hash': self.llm_analysis_prompt_hash
        }