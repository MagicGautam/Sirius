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

> 💡 *"Security isn’t just about automation—it’s about understanding."* This dashboard brings intelligence and clarity to the noisy world of vulnerability management.

---

