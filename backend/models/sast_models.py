# backend/models/sast_models.py

from datetime import datetime
# Import the shared Base instance
from backend.models import db
from sqlalchemy import Column, Integer, String, Text, DateTime, Float, ForeignKey, UniqueConstraint
from sqlalchemy.orm import relationship

class SastScan(db.Model):
    __tablename__ = 'sast_scans'
    __bind_key__ = 'sast_db'  
    id = Column(Integer, primary_key=True)
    scan_timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    project_name = Column(String(255), nullable=False)
    total_vulnerabilities_found = Column(Integer, default=0)
    report_hash = Column(String(64), unique=True, nullable=False)

    findings = relationship('SastFinding', backref='sast_scans', lazy=True)

    def __repr__(self):
        return f"<SastScan {self.id} - {self.project_name} @ {self.scan_timestamp}>"
    
    def to_dict(self):
        return {
            'id': self.id,
            'scan_timestamp': self.scan_timestamp.isoformat() if self.scan_timestamp else None,
            'project_name': self.project_name,
            'report_hash': self.report_hash
        }

class SastFinding(db.Model): 
    __tablename__ = 'sast_findings'
    __bind_key__ = 'sast_db' 

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('sast_scans.id'), nullable=True) 

    rule_id = Column(String(255), nullable=False)
    severity = Column(String(50), nullable=False)
    file_path = Column(String(500), nullable=False)
    line_number = Column(Integer, nullable=False)
    description = Column(Text)
    code_snippet = Column(Text)
    scanner_suggested_fix = Column(Text)

    llm_analysis_summary = Column(Text, nullable=True)
    llm_analysis_recommendations = Column(Text, nullable=True)
    llm_analysis_risk_score = Column(Float, nullable=True) 
    llm_analysis_timestamp = Column(DateTime, nullable=True)
    llm_analysis_status = Column(String(50), nullable=True)
    llm_analysis_prompt_hash = Column(String(64), nullable=True) 
    
    __table_args__ = (
        UniqueConstraint('scan_id', 'rule_id', 'file_path', 'line_number', name='_sast_finding_uc'),
    )


    def __repr__(self):
        return f"<SastFinding {self.id} - {self.rule_id} - {self.file_path}:{self.line_number}>"
    
    def to_dict(self):
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'rule_id': self.rule_id,
            'severity': self.severity,
            'file_path': self.file_path,
            'line_number': self.line_number,
            'description': self.description,
            'code_snippet': self.code_snippet,
            'scanner_suggested_fix': self.scanner_suggested_fix,
            'llm_analysis_summary': self.llm_analysis_summary,
            'llm_analysis_recommendations': self.llm_analysis_recommendations,
            'llm_analysis_risk_score': self.llm_analysis_risk_score,
            'llm_analysis_timestamp': self.llm_analysis_timestamp.isoformat() if self.llm_analysis_timestamp else None,
            'llm_analysis_status': self.llm_analysis_status,
            'llm_analysis_prompt_hash': self.llm_analysis_prompt_hash
        }