from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import os

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False 

db= SQLAlchemy(app)

class Vulnerability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_type = db.Column(db.String(50), nullable=False) # e.g., 'sast', 'sca', 'container', 'dast'
    tool = db.Column(db.String(50)) # e.g., 'semgrep', 'syft', 'trivy', 'zap'
    finding_id = db.Column(db.String(255), unique=True, nullable=False) # A unique ID from the tool report
    severity = db.Column(db.String(20)) # e.g., 'HIGH', 'MEDIUM', 'LOW'
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    file_path = db.Column(db.String(255)) # Relevant for SAST
    line_number = db.Column(db.Integer) # Relevant for SAST
    cve_id = db.Column(db.String(50)) # For SCA/Container
    package_name = db.Column(db.String(255)) # For SCA
    version = db.Column(db.String(50)) # For SCA
    cvss_score = db.Column(db.Float) # For SCA/Container

    def __repr__(self):
        return f"Vulnerability('{self.scan_type}', '{self.tool}', '{self.title}', '{self.severity}')"


    def to_dict(self):
        return {
            'id': self.id,
            'scan_type': self.scan_type,
            'tool': self.tool,
            'finding_id': self.finding_id,
            'severity': self.severity,
            'title': self.title,
            'description': self.description,
            'file_path': self.file_path,
            'line_number': self.line_number,
            'cve_id': self.cve_id,
            'package_name': self.package_name,
            'version': self.version,
            'cvss_score': self.cvss_score
        }
    

#-----API-ENDPOINTS----------

@app.route('/api/ingest/<scan_type>', methods=['POST'])
def ingest_report(scan_type):
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400

    report_data = request.get_json()

    if not report_data:
        return jsonify({"error": "No data provided in report"}), 400

    # For demonstration, let's just save a raw report to a file
    # In a real scenario, you'd parse report_data and store individual findings in the DB.
    # We'll implement the parsing and DB storage in the next steps.

    # For now, let's simulate storing some data
    # This is a placeholder for actual parsing and DB insertion logic
    try:
        for item in report_data.get('findings', []): # Assuming 'findings' key in report
            # A very basic example of extracting data
            new_finding = Vulnerability(
                scan_type=scan_type,
                tool=report_data.get('tool', 'unknown'), # Get tool from report, default to 'unknown'
                finding_id=item.get('id', os.urandom(8).hex()), # Use existing ID or generate one
                severity=item.get('severity', 'UNKNOWN'),
                title=item.get('title', 'No Title'),
                description=item.get('description', 'No Description'),
                file_path=item.get('file_path'),
                line_number=item.get('line_number'),
                cve_id=item.get('cve_id'),
                package_name=item.get('package_name'),
                version=item.get('version'),
                cvss_score=item.get('cvss_score')
            )
            db.session.add(new_finding)
        db.session.commit()
        return jsonify({"message": f"Report for {scan_type} ingested successfully (basic save to DB).", "count": len(report_data.get('findings', []))}), 200
    except Exception as e:
        db.session.rollback() # Rollback on error
        # Check for unique constraint violation (e.g., if finding_id is duplicated)
        if "UNIQUE constraint failed" in str(e):
             return jsonify({"error": f"Data already exists or duplicate finding_id for {scan_type}: {str(e)}"}), 409 # Conflict
        return jsonify({"error": f"Failed to ingest report for {scan_type}: {str(e)}"}), 500


@app.route('/api/findings/<scan_type>', methods=['GET'])
def get_findings(scan_type):
    findings = Vulnerability.query.filter_by(scan_type=scan_type).all()
    return jsonify([f.to_dict() for f in findings]), 200

@app.route('/')
def home():
    return "DevSecOps Dashboard Backend - Running!"

# --- Database Initialization ---
# This will create the database tables if they don't exist
with app.app_context():
    db.create_all()
    print("Database tables created/updated.")


if __name__ == '__main__':
    app.run(debug=True, port=5000, host='0.0.0.0') # Run in debug mode for development