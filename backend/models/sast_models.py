# backend/models/sast_models.py

from datetime import datetime
# Import the shared Base instance
from backend.models import db
from sqlalchemy import Column, Integer, String, Text, DateTime, Float, ForeignKey
from sqlalchemy import UniqueConstraint # Import UniqueConstraint

import hashlib

class SastFinding(db.Model): # <--- CHANGED: Inherit from Base
    __tablename__ = 'sast_findings'
    __bind_key__ = 'sast_db' # <--- NEW/RE-ADDED: Assign bind key for SAST database

    id = Column(Integer, primary_key=True)
    scan_id = Column(String(255), nullable=True) # Assuming scan_id is a unique identifier from the report
    rule_id = Column(String(255), nullable=False)
    severity = Column(String(50), nullable=False)
    file_path = Column(String(500), nullable=False)
    line_number = Column(Integer, nullable=False)
    description = Column(Text)
    code_snippet = Column(Text)
    scanner_suggested_fix = Column(Text)

    # LLM Analysis fields (nullable to allow for findings without immediate LLM analysis)
    llm_analysis_summary = Column(Text, nullable=True)
    llm_analysis_recommendations = Column(Text, nullable=True)
    llm_analysis_risk_score = Column(Float, nullable=True) # Example: 0.0 to 1.0 or 1-10
    llm_analysis_timestamp = Column(DateTime, nullable=True)
    llm_analysis_status = Column(String(50), nullable=True) # E.g., 'pending', 'completed', 'error'
    llm_analysis_prompt_hash = Column(String(64), nullable=True) # Hash of the prompt used for analysis

    unique_finding_key = Column(String(64), unique=True, nullable=False) # Hash of critical finding data

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
            'llm_analysis_prompt_hash': self.llm_analysis_prompt_hash,
            'unique_finding_key': self.unique_finding_key
        }