# 🛡️ SIRIUS - Overview

Welcome to the **Sirius Vulnerability Dashboard**, a powerful, intelligent web-based tool designed to streamline and enrich the analysis of security scan reports.

This project integrates automated ingestion of findings from various security scanners, leverages the capabilities of **local Large Language Models (LLMs)** via Ollama for human-readable insights, and implements efficient **caching mechanisms** to reduce redundancy and improve performance.

---

## 🚀 Project Vision

Security tools generate a lot of raw data—but making sense of it can be time-consuming and technically overwhelming. This dashboard aims to:

- **Ingest and store** vulnerability findings from scanners like Semgrep.
- **Enrich findings** with actionable, human-readable analysis using LLMs.
- **Optimize efficiency** by caching LLM responses intelligently.
- Lay the groundwork for a full-featured **DevSecOps visualization and triage interface**.

---

## 🔧 Architecture Overview

This project follows a modular, phased approach:

### 🧩 Phase 1: Core Ingestion System

- **Flask Backend Setup**: A minimal yet scalable Flask app (`backend/app.py`) serves as the core service layer.
- **Database with SQLAlchemy & SQLite**:
  - Configured via `backend/config.py` and `backend/extensions.py`.
  - Defines `SastFinding` model (`backend/models/sast_models.py`) to represent SAST vulnerabilities.
- **SAST Report Ingestion**:
  - POST endpoint: `/api/ingest/sast`
  - Accepts Semgrep-style JSON reports.
  - Deduplicates and persists findings in the database.
- **Findings Retrieval**:
  - GET endpoint: `/api/findings/sast`
  - Lists all ingested SAST findings for frontend/API consumption.

---

### 🧠 Phase 2: LLM-Powered Intelligence

- **Why LLMs?**
  - Raw scanner output lacks context, severity impact, or actionable steps.
  - LLMs help translate findings into readable, useful explanations.

- **Tech Decision**: Shifted from heavy dependencies (`transformers`, `torch`) to **[Ollama](https://ollama.com/)** for lightweight local inference.

- **LLM Integration (Gemma-3B via Ollama)**:
  - Ollama runs as a local LLM server at `http://localhost:11434`.
  - Communicated via `backend/services/llm_service.py`.

- **LLM Endpoint**:
  - GET `/api/llm/analyze/sast/<finding_id>`
  - Fetches finding → Builds prompt → Sends to Ollama → Returns analysis.

---

### ⚡ Phase 3: Caching for Speed & Efficiency

- **Problem**: Recomputing LLM responses wastes time and compute.
- **Solution**: Implemented caching using:
  - `llm_analysis_content`: Stores generated analysis.
  - `llm_analysis_prompt_hash`: Stores SHA256 hash of prompt.

- **Cache Logic** (inside `app.py`):
  - If matching hash exists → Serve from cache.
  - If not → Generate via Ollama → Save result & hash to DB.

---

## ✅ Key Highlights

- 📦 **Lightweight Backend**: Uses Flask, SQLite, and SQLAlchemy—ideal for local development and extensibility.
- 🤖 **AI-Powered Analysis**: Local LLM removes need for external APIs and enables offline operation.
- ⚙️ **Intelligent Caching**: Smart reuse of LLM outputs ensures resource optimization.
- 📊 **Modular Design**: Built for extension to DAST, SCA, and container scan data in future phases.

---

## 🧭 Next Steps (Coming Soon)

- Extend model structure for:
  - DAST findings (e.g., OWASP ZAP)
  - Container vulnerabilities (e.g., Trivy)
  - SBOM-based issues (e.g., Syft)
- Add frontend for interactive triaging.
- Implement user authentication and access control (JWT-based).
- Deploy via Docker and integrate with CI/CD pipelines.

---

---

Conversation Log - LLM Caching & Model Design (July 11 - July 15, 2025)
Context: User is developing a Flask backend application (SIRIUS) to ingest security scanner reports (Trivy for containers, SAST) and enrich findings with LLM analysis using Ollama.

Key Issues & Resolutions:

Initial Problem: AttributeError: 'str' object has no attribute 'get' in container_service.py when processing cvss.get().

Root Cause: The cvss variable in the loop was sometimes a string instead of a dictionary, indicating malformed or unexpected data structure for CVSS within the Trivy report.

Resolution: Added isinstance(cvss, dict) check within the cvss_metrics loop in ingest_trivy_report to ensure cvss is a dictionary before calling .get(). Also added a check for cvss_metrics itself to ensure it's a list.

Second Problem: AttributeError: 'ContainerService' object has no attribute 'get_all_findings' when calling /api/findings/container.

Root Cause: get_all_findings (and other getter methods) were incorrectly indented, placing them outside the ContainerService class definition.

Resolution: Corrected indentation of all getter methods (get_all_findings, get_findings_by_scan_id, get_scan_by_id, get_findings_for_scan) to be properly nested within the ContainerService class.

Third Problem: AttributeError: 'ContainerFinding' object has no attribute 'todict' when retrieving findings.

Root Cause: The ContainerFinding (and likely ContainerScan, CVERichment) models lacked a to_dict() method, but the service layer was calling f.todict(). There was also a typo (todict vs to_dict).

Resolution:

Defined to_dict() methods for ContainerScan, ContainerFinding, and CVERichment models in backend/Container_models.py to serialize ORM objects into dictionaries for API responses.

Corrected all calls from todict() to to_dict() in backend/services/container_service.py.

Fourth Problem (Current Focus): WARNING:backend:Finding object for container ID 1 does not support LLM analysis fields. Analysis not saved to DB.

Root Cause 1 (Primary): The ContainerFinding table in the SQLite database did not have the new columns (llm_analysis_summary, llm_analysis_recommendations, etc.) because the database file (container.db) was not recreated after adding these fields to backend/Container_models.py.

Resolution 1: Instructed user to delete ~/SIRIUS/backend/databases/container.db and restart the Flask application, forcing db.create_all() to recreate tables with the new schema.

Root Cause 2 (Secondary - LLM Logic): The LLMService.generate_analysis method returned a raw string, which then needed parsing into distinct summary, recommendations, etc., before saving. The route was attempting to assign these before parsing.

Resolution 2:

Modified LLMService.generate_analysis to call a new private method _parse_llm_output.

Implemented _parse_llm_output to use regex to extract content under Markdown headings (### Vulnerability Summary, ### Remediation, etc.) and return a structured dictionary.

Adjusted generate_analysis to return this structured dictionary.

Updated the Flask route (/api/llm/analyze/container/<int:finding_id>) to correctly retrieve and save the parsed fields from the returned dictionary to the ContainerFinding object.

Fifth Problem (Current Discussion): User raises concern about "1 Container Finding has Multiple CVEs" and suggests caching LLM analysis on CVERichment instead of ContainerFinding.

Analysis: Based on the current ContainerFinding model (single ForeignKey to CVERichment), each ContainerFinding is linked to one CVE. The LLM prompt for container findings is highly contextual (includes package name, installed version, fixed version, etc.).

Decision: Reaffirmed that caching LLM analysis directly on the ContainerFinding model is the most appropriate approach, as the analysis is specific to the instance of the vulnerability (CVE + package + version + scan context). Caching on CVERichment would lead to loss of context and potential conflicts.

Future Enhancement for Caching Robustness: Proposed adding a llm_analysis_prompt_hash column to ContainerFinding to store a hash of the exact prompt used, allowing for intelligent cache invalidation if the prompt content (derived from finding details) changes. This will be implemented in the next steps.

Clarification Needed: Asked the user to clarify if their ingestion logic truly consolidates multiple CVEs into a single ContainerFinding record, or if multiple ContainerFinding records are created for different CVEs affecting the same package/version. This will help confirm the model alignment.

Next Steps (as of last message):

Implement llm_analysis_prompt_hash column in ContainerFinding.

Crucially, delete container.db and restart Flask app.

Implement _parse_llm_output and modify generate_analysis in LLMService.

Implement get_or_generate_llm_analysis_for_finding in ContainerService.

Update routes.py to use the new ContainerService method.

Re-ingest data and test.