# backend/models.py

from datetime import datetime
from . import db # Assuming your db object is initialized in __init__.py and imported like this
import hashlib # For hashing scan reports

class ContainerScan(db.Model):
    __tablename__ = 'container_scans'
    id = db.Column(db.Integer, primary_key=True)
    scan_timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    image_name = db.Column(db.String(255), nullable=False)
    image_digest = db.Column(db.String(255)) # Often available in Trivy reports
    os_family = db.Column(db.String(50))
    os_name = db.Column(db.String(50))
    total_vulnerabilities_found = db.Column(db.Integer, default=0)
    # A hash of the full raw report, useful for detecting re-ingestion of identical reports
    report_hash = db.Column(db.String(64), unique=True, nullable=False) # SHA256 hash

    # Relationship to individual findings
    findings = db.relationship('ContainerFinding', backref='container_scan', lazy=True)

    def __repr__(self):
        return f"<ContainerScan {self.id} - {self.image_name} @ {self.scan_timestamp}>"

class ContainerFinding(db.Model):
    __tablename__ = 'container_findings'
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('container_scans.id'), nullable=False)

    # Core vulnerability details from Trivy
    vulnerability_id = db.Column(db.String(50), nullable=False) # e.g., CVE-2020-15999
    pkg_name = db.Column(db.String(255), nullable=False)
    installed_version = db.Column(db.String(100), nullable=False)
    fixed_version = db.Column(db.String(100))
    severity = db.Column(db.String(20), nullable=False) # e.g., MEDIUM, HIGH, CRITICAL
    title = db.Column(db.String(500))
    description = db.Column(db.Text)
    primary_url = db.Column(db.String(500))

    # CVSS Scores (from NVD if available)
    cvss_nvd_v2_vector = db.Column(db.String(255))
    cvss_nvd_v2_score = db.Column(db.Float)
    cvss_nvd_v3_vector = db.Column(db.String(255))
    cvss_nvd_v3_score = db.Column(db.Float)

    # Published and Last Modified Dates from Trivy/NVD
    published_date = db.Column(db.DateTime)
    last_modified_date = db.Column(db.DateTime)

    # Unique key for a finding across scans (vulnerability + package)
    # This helps identify if CVE-X affecting pkg-Y has already been seen, regardless of the scan it came from
    unique_finding_key = db.Column(db.String(64), unique=False, nullable=False) # Will be a hash

    # Composite unique constraint to prevent duplicate *identical* findings within the *same scan*
    # (though our ingestion logic will prevent this anyway) and across all findings based on core details
    # We will hash these for the unique_finding_key to make the index shorter
    __table_args__ = (
        db.UniqueConstraint('vulnerability_id', 'pkg_name', 'installed_version', 'scan_id', name='_trivy_finding_uc'),
    )

    # Relationship to cached CVE enrichment data
    # This can be null initially and populated later by CVEEnrichmentService
    cve_enrichment_id = db.Column(db.String(50), db.ForeignKey('cve_enrichment.cve_id'), nullable=True)
    cve_enrichment = db.relationship('CVERichment', backref='container_findings', lazy=True)


    def __repr__(self):
        return f"<ContainerFinding {self.id} - {self.vulnerability_id} in {self.pkg_name} ({self.installed_version})>"

class CVERichment(db.Model):
    __tablename__ = 'cve_enrichment'
    cve_id = db.Column(db.String(50), primary_key=True) # e.g., CVE-2020-15999
    description = db.Column(db.Text) # More detailed description from NVD
    cvss_v3_score = db.Column(db.Float)
    cvss_v3_vector = db.Column(db.String(255))
    cvss_v2_score = db.Column(db.Float)
    cvss_v2_vector = db.Column(db.String(255))
    cwe_id = db.Column(db.String(50)) # e.g., CWE-787
    published_date = db.Column(db.DateTime)
    last_modified_date = db.Column(db.DateTime)
    nvd_url = db.Column(db.String(500))
    # You could add more fields here if needed from NVD (e.g., exploitability metrics, impact metrics)

    def __repr__(self):
        return f"<CVERichment {self.cve_id}>"

# You might also need to update how your LLMSummary model references findings if it only had SAST findings before
# If it's general enough (e.g., using polymorphic association or separate FKs), you might not need to change it much.
# Let's assume for now it needs to be updated to link to ContainerFinding
# (You might have already had this from previous steps if it was general)
# If your LLMSummary looks like this:
# class LLMSummary(db.Model):
#     __tablename__ = 'llm_summaries'
#     id = db.Column(db.Integer, primary_key=True)
#     finding_type = db.Column(db.String(50), nullable=False) # 'sast_finding', 'container_finding'
#     finding_id = db.Column(db.Integer, nullable=False) # ID of the specific finding
#     summary_text = db.Column(db.Text, nullable=False)
#     generated_at = db.Column(db.DateTime, default=datetime.utcnow)
#     __table_args__ = (db.UniqueConstraint('finding_type', 'finding_id', name='_llm_summary_uc'),)
# Then it's already generic enough! If not, we can adjust it later.