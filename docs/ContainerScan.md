# 📥 Trivy Scan Ingestion & Analysis Flow

This section outlines the full methodology for how Container Image findings are ingested, analyzed using a local LLM (via Ollama), and cached for efficient retrieval.

---

### 1. 📐 Container Data Model

The system now uses a parent-child relationship to represent scan data, ensuring better organization and preventing redundancy:

* **`ContainerScan`**: Represents a single, complete Trivy report. This model stores high-level metadata such as the `image_name`, `os_name`, and a unique `report_hash` to prevent duplicate ingestion.
* **`ContainerFinding`**: Represents an individual vulnerability from a report. Each finding is linked to its parent scan via a foreign key (`scan_id`). It stores details like the `vulnerability_id`, `severity`, and `cve_data`.
* **`CVERichment`**: A lookup table used to store detailed CVE information, which is fetched from external sources and cached to prevent redundant API calls.

**LLM-specific fields for `ContainerFinding` include:**

- `llm_analysis_summary`: A brief, high-level summary of the vulnerability.
- `llm_analysis_recommendations`: Technical steps to fix the issue.
- `llm_analysis_risk_score`: A score assigned by the LLM (e.g., 1-10).
- `llm_analysis_timestamp`: The time of the last analysis.
- `llm_analysis_prompt_hash`: A SHA256 hash of the prompt used for caching.
- `llm_analysis_status`: Tracks the analysis state (e.g., 'pending', 'completed', 'failed').

---

### 2. 🔄 Ingestion Logic & API Endpoints

The ingestion process has been refactored into a robust two-part service logic to ensure data integrity and prevent redundancy. The API provides a comprehensive set of endpoints for managing this data.

#### Ingest Container Scan Report

* **Method:** `POST`
* **URL:** `/api/container/scans`
* **Description:** This is the main endpoint for submitting a complete Trivy vulnerability report in JSON format. The service will process the report, create a new `ContainerScan` record, and store all associated findings. The endpoint intelligently skips the ingestion process if the same report has already been submitted (based on a unique hash of the report).
* **Service Flow:** `ingest_trivy_report` creates the parent `ContainerScan` record, and then calls `ingest_container_finding` for each vulnerability to create the child records linked by `scan_id`.

#### Retrieve All Container Scans

* **Method:** `GET`
* **URL:** `/api/container/scans`
* **Description:** Returns a list of all `ContainerScan` records, providing a high-level overview of all reports that have been ingested.

#### Retrieve a Single Container Scan by Artifact Name

* **Method:** `GET`
* **URL:** `/api/container/scans/<string:artifactname>`
* **Description:** Fetches a specific `ContainerScan` record using its `image_name` (e.g., "my-nginx-app:1.0").

#### Retrieve Findings for a Specific Scan

* **Method:** `GET`
* **URL:** `/api/container/scans/<string:identifier>/findings`
* **Description:** This endpoint retrieves all findings for a specific scan. The `identifier` can be either the unique `scan_id` (an integer) or the `image_name` (e.g., "my-nginx-app:1.0"), making the API more flexible.

#### Retrieve a Single Container Finding by ID

* **Method:** `GET`
* **URL:** `/api/container/findings/<int:finding_id>`
* **Description:** Fetches a single `ContainerFinding` record by its unique `id` for detailed inspection.

---

### 3. 🧠 LLM Integration via Ollama

The system integrates a local LLM to transform raw CVE data into contextual, actionable intelligence. The LLM integration and caching strategy are identical to the SAST flow.

#### LLM Endpoint

* **Endpoint:** `GET /api/llm/analyze/container/<finding_id>`
* **Description:** When triggered, this endpoint performs or retrieves a cached LLM analysis for a given `ContainerFinding` and returns a structured response with a summary, remediation steps, and a risk score.

---

### 4. ⚡ LLM Caching Strategy

A robust, database-backed caching mechanism is implemented to optimize performance and prevent redundant LLM invocations. This ensures that the same analysis is not performed twice.

**Key features include:**

- **Prompt Hashing**: A SHA256 hash of the prompt is generated and stored with the analysis.
- **Cache Hit**: If a matching hash and a valid analysis exist, the cached content is served instantly.
- **Cache Miss**: If the cache is invalid, a new LLM request is made, and the new analysis is stored along with an updated timestamp and prompt hash.
- **Status Tracking**: The `llm_analysis_status` field tracks the state of the analysis request.

---

### ✅ Summary

| Step               | Description                                                                                             |
|--------------------|---------------------------------------------------------------------------------------------------------|
| Ingest             | Accepts a Trivy JSON report, checks for duplicates, creates a `ContainerScan`, and stores all new `ContainerFinding` records. |
| Analyze            | Generates a structured prompt from finding data and sends it to the LLM.                                    |
| Structure Response | Receives a Markdown response and parses it into `summary`, `recommendations`, and `risk_score`.         |
| Cache              | Stores the analysis, timestamp, and a prompt hash to prevent duplicate work.                               |
| Serve              | Returns cached results on demand or triggers new analysis if the cache is stale.                          |

---

> 🧠 *This container scan pipeline transforms raw security data into contextual, actionable, and structured intelligence—making triage and remediation significantly faster for developers and security teams.*