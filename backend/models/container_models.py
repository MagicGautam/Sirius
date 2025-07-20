# backend/Container_models.py

from datetime import datetime
# Import the single Base instance from backend.models
from backend.models import db
from sqlalchemy import Column, Integer, String, Text, DateTime, Float, ForeignKey, UniqueConstraint
from sqlalchemy.orm import relationship

class ContainerScan(db.Model):
    __tablename__ = 'container_scans'
    __bind_key__ = 'container_db' 
    id = Column(Integer, primary_key=True)
    scan_timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    image_name = Column(String(255), nullable=False)
    image_digest = Column(String(255))
    os_family = Column(String(50))
    os_name = Column(String(50))
    total_vulnerabilities_found = Column(Integer, default=0)
    report_hash = Column(String(64), unique=True, nullable=False)

    findings = relationship('ContainerFinding', backref='container_scan', lazy=True)

    def __repr__(self):
        return f"<ContainerScan {self.id} - {self.image_name} @ {self.scan_timestamp}>"
    
    def to_dict(self):
        return {
            'id': self.id,
            'scan_timestamp': self.scan_timestamp.isoformat() if self.scan_timestamp else None,
            'image_name': self.image_name,
            'image_digest': self.image_digest,
            'os_family': self.os_family,
            'os_name': self.os_name,
            'total_vulnerabilities_found': self.total_vulnerabilities_found,
            'report_hash': self.report_hash
        }

class ContainerFinding(db.Model): 
    __tablename__ = 'container_findings'
    __bind_key__ = 'container_db'
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('container_scans.id'), nullable=True)

    vulnerability_id = Column(String(50), nullable=False)
    pkg_name = Column(String(255), nullable=False)
    installed_version = Column(String(100), nullable=False)
    fixed_version = Column(String(100))
    severity = Column(String(20), nullable=False)
    title = Column(String(500))
    description = Column(Text)
    primary_url = Column(String(500))

    cvss_nvd_v2_vector = Column(String(255))
    cvss_nvd_v2_score = Column(Float)
    cvss_nvd_v3_vector = Column(String(255))
    cvss_nvd_v3_score = Column(Float)

    published_date = Column(DateTime)
    last_modified_date = Column(DateTime)

    llm_analysis_summary = Column(Text, nullable=True)
    llm_analysis_recommendations = Column(Text, nullable=True)
    llm_analysis_risk_score = Column(Float, nullable=True)
    llm_analysis_timestamp = Column(DateTime, nullable=True)
    llm_analysis_status = Column(String(50), nullable=True)
    llm_analysis_prompt_hash = Column(String(64), nullable=True)
    
    unique_finding_key = Column(String(64), unique=False, nullable=False)
    
    __table_args__ = (
        UniqueConstraint('vulnerability_id', 'pkg_name', 'installed_version', 'scan_id', name='_trivy_finding_uc'),
    )

    cve_enrichment_id = Column(String(50), ForeignKey('cve_enrichment.cve_id'), nullable=True)
    cve_enrichment = relationship('CVERichment', backref='container_findings', lazy=True)

    def __repr__(self):
        return f"<ContainerFinding {self.id} - {self.vulnerability_id} in {self.pkg_name} ({self.installed_version})>"
    
    def to_dict(self):
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'vulnerability_id': self.vulnerability_id,
            'pkg_name': self.pkg_name,
            'installed_version': self.installed_version,
            'fixed_version': self.fixed_version,
            'severity': self.severity,
            'title': self.title,
            'description': self.description,
            'primary_url': self.primary_url,
            'cvss_nvd_v2_vector': self.cvss_nvd_v2_vector,
            'cvss_nvd_v2_score': self.cvss_nvd_v2_score,
            'cvss_nvd_v3_vector': self.cvss_nvd_v3_vector,
            'cvss_nvd_v3_score': self.cvss_nvd_v3_score,
            'published_date': self.published_date.isoformat() if self.published_date else None,
            'last_modified_date': self.last_modified_date.isoformat() if self.last_modified_date else None,
            'unique_finding_key': self.unique_finding_key,
            'llm_analysis_summary': self.llm_analysis_summary,
            'llm_analysis_recommendations': self.llm_analysis_recommendations,
            'llm_analysis_risk_score': self.llm_analysis_risk_score,
            'llm_analysis_timestamp': self.llm_analysis_timestamp.isoformat() if self.llm_analysis_timestamp else None,
            'llm_analysis_status': self.llm_analysis_status,
            'llm_analysis_prompt_hash': self.llm_analysis_prompt_hash,
            'cve_enrichment_id': self.cve_enrichment_id 
        }


class CVERichment(db.Model):
    __tablename__ = 'cve_enrichment'
    __bind_key__ = 'container_db' 
    cve_id = Column(String(50), primary_key=True)
    description = Column(Text)
    cvss_v3_score = Column(Float)
    cvss_v3_vector = Column(String(255))
    cvss_v2_score = Column(Float)
    cvss_v2_vector = Column(String(255))
    cwe_id = Column(String(50))
    published_date = Column(DateTime)
    last_modified_date = Column(DateTime)
    nvd_url = Column(String(500))

    def __repr__(self):
        return f"<CVERichment {self.cve_id}>"
    
    def to_dict(self):
        return {
            'cve_id': self.cve_id,
            'description': self.description,
            'cvss_v3_score': self.cvss_v3_score,
            'cvss_v3_vector': self.cvss_v3_vector,
            'cvss_v2_score': self.cvss_v2_score,
            'cvss_v2_vector': self.cvss_v2_vector,
            'cwe_id': self.cwe_id,
            'published_date': self.published_date.isoformat() if self.published_date else None,
            'last_modified_date': self.last_modified_date.isoformat() if self.last_modified_date else None,
            'nvd_url': self.nvd_url
        }