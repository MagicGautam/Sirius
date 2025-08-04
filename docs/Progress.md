# 🛡️ SIRIUS - Vulnerability Dashboard

Welcome to the **Sirius Vulnerability Dashboard**, a powerful, intelligent web-based tool designed to streamline and enrich the analysis of security scan reports.

This project integrates automated ingestion of findings from various security scanners, leverages the capabilities of **local Large Language Models (LLMs)** via Ollama for human-readable insights, and implements efficient **caching mechanisms** to reduce redundancy and improve performance.

---

## 🚀 Project Vision

Security tools generate a lot of raw data—but making sense of it can be time-consuming and technically overwhelming. This dashboard aims to:

- **Ingest and store** vulnerability findings from scanners like Semgrep and Trivy.
- **Enrich findings** with actionable, human-readable analysis using LLMs.
- **Optimize efficiency** by caching LLM responses intelligently.
- Lay the groundwork for a full-featured **DevSecOps visualization and triage interface**.

---

## 🔧 Architecture Overview

This project has evolved through a modular, phased approach to build a robust and extensible backend.

### 🧩 Phase 1: Core SAST System

- **Flask Backend Setup**: A scalable Flask application (`backend/app.py`) serves as the core service layer.
- **Database with SQLAlchemy & SQLite**:
  - The database schema is now defined by two models: a parent `SastScan` model for each report and a child `SastFinding` model for each vulnerability.
  - A one-to-many relationship links findings to their parent scan via a foreign key (`scan_id`).
- **SAST Report Ingestion**:
  - **POST endpoint:** `/api/sast/scans`
  - Accepts Semgrep-style JSON reports.
  - A unique hash of the report prevents duplicate ingestion, and a new `SastScan` record is created for each unique report.
- **SAST Findings Retrieval**:
  - **GET endpoints:**
    - `/api/sast/scans` to list all ingested scans.
    - `/api/sast/scans/<int:scan_id>/findings` to get all findings for a specific scan.
    - `/api/sast/findings/<int:finding_id>` to get a single finding by its unique ID.

### 🧠 Phase 2: LLM-Powered Intelligence & Caching

- **Why LLMs?**
  - Raw scanner output lacks context, severity impact, or actionable steps.
  - LLMs help translate findings into readable, useful explanations.
- **Tech Decision**: Shifted from heavy dependencies (`transformers`, `torch`) to **[Ollama](https://ollama.com/)** for lightweight local inference.
- **LLM Integration**:
  - Communicated via `backend/services/llm_service.py`, which includes a new `_parse_llm_output` method to structure responses.
  - The analysis is parsed into separate fields: `llm_analysis_summary`, `llm_analysis_recommendations`, and `llm_analysis_risk_score`.
- **LLM Endpoint**:
  - **GET** `/api/llm/analyze/<scan_type>/<int:finding_id>` (e.g., `/api/llm/analyze/sast/1`).
  - This endpoint fetches a finding, checks the cache, and either serves a cached response or generates a new one.
- **Caching Logic**:
  - Implemented with a `llm_analysis_prompt_hash` column to store a SHA256 hash of the exact prompt.
  - The analysis is served from the database if the prompt hash matches, ensuring intelligent cache invalidation if the finding details change.

### 📦 Phase 3: Container Scan Support

- **New Data Models**:
  - **`ContainerScan`**: A parent model to represent a single Trivy report.
  - **`ContainerFinding`**: A child model for each vulnerability, linked via `scan_id`.
  - **`CVERichment`**: A model to cache detailed CVE information.
- **Container Report Ingestion**:
  - **POST endpoint:** `/api/container/scans`
  - Accepts Trivy-style JSON reports.
  - Deduplicates and persists findings, creating a new `ContainerScan` record for each unique report.
- **Container Findings Retrieval**:
  - **GET endpoints:**
    - `/api/container/scans` to list all container scans.
    - `/api/container/scans/<string:identifier>/findings` to get all findings for a scan, using either `scan_id` or `image_name`.
    - `/api/container/findings/<int:finding_id>` to get a single finding by its unique ID.

---

## ✅ Key Highlights

- 📦 **Lightweight Backend**: Uses Flask, SQLite, and SQLAlchemy—ideal for local development and extensibility.
- 🤖 **AI-Powered Analysis**: Local LLM removes the need for external APIs and enables offline operation.
- ⚙️ **Intelligent Caching**: Smart reuse of LLM outputs ensures resource optimization and speed.
- 📊 **Modular Design**: Extended to support SAST and Container scan data with clear, RESTful API endpoints.

---

## 🗓️ Conversation & Progress Log

### July 11 - July 15, 2025

**Context**: User is developing a Flask backend application (SIRIUS) to ingest security scanner reports (Trivy for containers, SAST) and enrich findings with LLM analysis using Ollama.

**Problem 1: `AttributeError: 'str' object has no attribute 'get'` in `container_service.py`**
* **Root Cause**: The `cvss` variable from the Trivy report was sometimes a string instead of a dictionary, causing the `cvss.get()` call to fail.
* **Resolution**: Added `isinstance(cvss, dict)` checks to ensure a valid dictionary before accessing its keys.

**Problem 2: `AttributeError: 'ContainerService' object has no attribute 'get_all_findings'`**
* **Root Cause**: Several getter methods were incorrectly indented, placing them outside the `ContainerService` class definition.
* **Resolution**: Corrected the indentation of all service methods to be properly nested within the class.

**Problem 3: `AttributeError: 'ContainerFinding' object has no attribute 'todict'`**
* **Root Cause**: The models lacked a `to_dict()` method, and the service layer had a typo (`todict` vs. `to_dict`).
* **Resolution**: Implemented `to_dict()` methods for `ContainerScan`, `ContainerFinding`, and `CVERichment` models and corrected all service calls to use `to_dict()`.

**Problem 4: `FATAL ERROR during Flask-SQLAlchemy db.create_all(): NoReferencedTableError`**
* **Root Cause**: The `ForeignKey` reference in `SastFinding` had a typo, referencing `sast_scan` instead of `sast_scans`.
* **Resolution**: Corrected the `ForeignKey` string in `sast_models.py` to match the `__tablename__` of the parent model (`sast_scans.id`). The database file was deleted and recreated to apply the new schema.

**Problem 5: `404 Not Found` when retrieving a container scan by artifact name.**
* **Root Cause**: The `get_scan_by_artifact_name` method was incorrectly querying by `id` instead of `image_name`.
* **Resolution**: Modified the query to `filter_by(image_name=artifact_name)`.

**Problem 6: User seeks to modify `get_findings_for_scan` to use `artifact_name`.**
* **Root Cause**: The existing method only accepted an integer `scan_id`.
* **Resolution**: Refactored the method to accept a string `identifier`, which first tries to parse it as an `int` for an `id` lookup and falls back to a `string` lookup by `image_name`. Corrected the corresponding endpoint in `routes.py`.

**Problem 7: How do unique `id`s work across multiple scans?**
* **Root Cause**: User was unsure if `id`s would be redundant across different parent scans in a one-to-many relationship.
* **Resolution**: Confirmed that `id` is a primary key and is globally unique for every row in the `sast_findings` table. The `scan_id` foreign key is what links multiple findings to a single parent scan.

**Problem 8: How are `id`s assigned during ingestion?**
* **Root Cause**: User was curious about the mechanics of `id` generation.
* **Resolution**: Explained that the database's auto-incrementing primary key mechanism handles this automatically when a new object is committed to the session, ensuring a unique and incremental `id` for each new finding.

---

## 🧭 Next Steps (Coming Soon)

- Finalize the unified frontend for interactive triage and visualization.
- Implement user authentication and access control (JWT-based).
- Containerize the application using Docker and integrate with CI/CD pipelines.
- Expand security scanner integrations (e.g., DAST, SCA).