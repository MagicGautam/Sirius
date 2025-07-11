# backend/Container_models.py

from datetime import datetime
from backend.models import db
import hashlib # For hashing scan reports

class ContainerScan(db.Model):
    __bind_key__ = 'container_db' 
    __tablename__ = 'container_scans'
    id = db.Column(db.Integer, primary_key=True)
    scan_timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    image_name = db.Column(db.String(255), nullable=False)
    image_digest = db.Column(db.String(255))
    os_family = db.Column(db.String(50))
    os_name = db.Column(db.String(50))
    total_vulnerabilities_found = db.Column(db.Integer, default=0)
    report_hash = db.Column(db.String(64), unique=True, nullable=False)

    findings = db.relationship('ContainerFinding', backref='container_scan', lazy=True)

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
    __bind_key__ = 'container_db' 
    __tablename__ = 'container_findings'
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('container_scans.id'), nullable=False)

    vulnerability_id = db.Column(db.String(50), nullable=False)
    pkg_name = db.Column(db.String(255), nullable=False)
    installed_version = db.Column(db.String(100), nullable=False)
    fixed_version = db.Column(db.String(100))
    severity = db.Column(db.String(20), nullable=False)
    title = db.Column(db.String(500))
    description = db.Column(db.Text)
    primary_url = db.Column(db.String(500))

    cvss_nvd_v2_vector = db.Column(db.String(255))
    cvss_nvd_v2_score = db.Column(db.Float)
    cvss_nvd_v3_vector = db.Column(db.String(255))
    cvss_nvd_v3_score = db.Column(db.Float)

    published_date = db.Column(db.DateTime)
    last_modified_date = db.Column(db.DateTime)

    unique_finding_key = db.Column(db.String(64), unique=False, nullable=False)

    __table_args__ = (
        db.UniqueConstraint('vulnerability_id', 'pkg_name', 'installed_version', 'scan_id', name='_trivy_finding_uc'),
    )

    cve_enrichment_id = db.Column(db.String(50), db.ForeignKey('cve_enrichment.cve_id'), nullable=True)
    cve_enrichment = db.relationship('CVERichment', backref='container_findings', lazy=True)

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
            'cve_enrichment_id': self.cve_enrichment_id # Include this if you intend to use it in API responses
            # 'cve_enrichment': self.cve_enrichment.to_dict() if self.cve_enrichment else None # Optionally, nest related CVE data
        }


class CVERichment(db.Model):
    __bind_key__ = 'container_db' 
    __tablename__ = 'cve_enrichment'
    cve_id = db.Column(db.String(50), primary_key=True)
    description = db.Column(db.Text)
    cvss_v3_score = db.Column(db.Float)
    cvss_v3_vector = db.Column(db.String(255))
    cvss_v2_score = db.Column(db.Float)
    cvss_v2_vector = db.Column(db.String(255))
    cwe_id = db.Column(db.String(50))
    published_date = db.Column(db.DateTime)
    last_modified_date = db.Column(db.DateTime)
    nvd_url = db.Column(db.String(500))

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
