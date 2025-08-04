## 📥 SAST Scan Ingestion & Analysis Flow

This section outlines the full methodology for how SAST findings are ingested, analyzed using a local LLM (via Ollama), and cached for efficient retrieval.

---

### 1. 📐 SAST Data Model

To structure the data, the system now uses a parent-child relationship between two models:

* **`SastScan`**: Represents a single, complete SAST report. It stores high-level metadata such as a unique `project_name` and a `report_hash` to prevent duplicate ingestion.
* **`SastFinding`**: Represents an individual vulnerability or finding from a report. Each finding is linked to its parent scan via a foreign key (`scan_id`).

**Each finding stores key metadata such as:**

- Rule ID
- File path and line number
- Severity and description
- Code snippet and suggested fix (if available)
- Timestamp of ingestion

**LLM-specific fields include:**

- `llm_analysis_summary`: A brief, high-level summary of the vulnerability.
- `llm_analysis_recommendations`: Technical steps to fix the issue.
- `llm_analysis_risk_score`: A score assigned by the LLM (e.g., 1-10).
- `llm_analysis_timestamp`: The time of the last analysis.
- `llm_analysis_prompt_hash`: A SHA256 hash of the prompt used for analysis, crucial for caching.
- `llm_analysis_status`: Tracks the analysis state (e.g., 'pending', 'completed', 'failed').

A unique constraint ensures that duplicate findings **within a single scan** are not inserted multiple times.

---

### 2. 🔄 SAST Report Ingestion

**Endpoint:** `POST /api/sast/scans`  
**Backend Services:** `sast_service.py`, `app.py`

This API endpoint accepts raw JSON reports (e.g., from Semgrep) and manages the full ingestion process. The logic now works as follows:

- **Report Hashing**: A unique SHA256 hash of the entire report is generated. If a `SastScan` with this hash already exists, the ingestion is skipped entirely.
- **Scan Creation**: If it's a new report, a `SastScan` entry is created with the provided `project_name` and the new hash.
- **Finding Ingestion**: The report's findings are then parsed, extracted, and stored as `SastFinding` records, each linked to the new `SastScan` via its `scan_id`.

This new two-step process is more robust, preventing duplicate work at the report level and ensuring data is organized by scan.

---

### 3. 🧠 LLM Integration via Ollama

To transform raw technical findings into actionable intelligence, the system integrates a local LLM served by Ollama.

#### Why Ollama?

- **Lightweight**: Avoids heavy Python dependencies like `transformers` or `torch`.
- **Local-first**: No cloud costs or latency.
- **Simple API**: Accessible via HTTP endpoints for easy backend integration.

#### Prompt Engineering Strategy

Each prompt sent to the LLM includes:

- Rule ID
- A detailed description of the issue
- File context and code snippet
- Severity and any suggested fix

To ensure consistency, the prompt instructs the model to provide a structured Markdown response with the following sections, which are then parsed into the new database fields:

- `### Vulnerability Summary` (for `llm_analysis_summary`)
- `### Remediation` (for `llm_analysis_recommendations`)
- `### Risk Score` (for `llm_analysis_risk_score`)

#### LLM Endpoint

- **Endpoint:** `GET /api/llm/analyze/sast/<finding_id>`
- When triggered, it:
  - Fetches the relevant finding from the database.
  - Checks the caching status.
  - Generates a structured prompt if needed.
  - Sends it to Ollama’s `/api/generate`.
  - Parses the response and populates the `llm_analysis_*` fields.

---

### 4. ⚡ LLM Caching Strategy

To optimize performance and prevent redundant LLM invocations, a database-backed caching mechanism is implemented.

#### How It Works

1. **Status Check**: The method first checks the `llm_analysis_status` and `llm_analysis_timestamp` on the finding.
2. **Prompt Hashing**: A consistent prompt is generated for the finding and a SHA256 hash of the prompt is calculated.
3. **Cache Check**:
   - If the `llm_analysis_status` is 'completed', the timestamp is recent (e.g., within 7 days), **and** the `llm_analysis_prompt_hash` matches,
   - Then the cached analysis (summary, recommendations, risk score) is served instantly.
4. **Cache Miss**:
   - If the cache is invalid, a new LLM request is made. The finding's status is updated to 'pending', and upon completion, the new analysis is stored along with a fresh timestamp and prompt hash.

#### Benefits

- **Speed**: Frequent requests for the same finding are served instantly.
- **Accuracy**: If any detail in the finding changes, a new hash is generated and fresh analysis is performed.
- **Efficiency**: Reduces unnecessary load on the LLM engine, especially when dealing with large sets of vulnerabilities.

---

### ✅ Summary

| Step               | Description                                                                                             |
|--------------------|---------------------------------------------------------------------------------------------------------|
| Ingest             | Accepts a JSON report, checks for duplicates, creates a `SastScan`, and stores all new `SastFinding` records. |
| Analyze            | Generates a structured prompt from finding data and sends it to the LLM.                                    |
| Structure Response | Receives a Markdown response and parses it into `summary`, `recommendations`, and `risk_score`.         |
| Cache              | Stores the analysis, timestamp, and a prompt hash to prevent duplicate work.                               |
| Serve              | Returns cached results on demand or triggers new analysis if the cache is stale.                          |

---

> 🧠 *This SAST+LLM pipeline transforms raw security data into contextual, actionable, and structured intelligence—making triage and remediation significantly faster for developers and security teams.*