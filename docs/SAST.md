## 📥 SAST Scan Ingestion & Analysis Flow

This section outlines the full methodology for how SAST findings are ingested, analyzed using a local LLM (via Ollama), and cached for efficient retrieval.

---

### 1. 📐 SAST Data Model

The system defines a `SastFinding` model in the backend to represent individual vulnerabilities. Each finding stores metadata such as:

- Rule ID
- File path and line number
- Severity and description
- Code snippet and suggested fix (if available)
- Timestamp of ingestion

**LLM-specific fields include:**

- `llm_analysis_content`: Stores the LLM's generated analysis.
- `llm_analysis_prompt_hash`: Stores a SHA256 hash of the generated prompt to detect changes and avoid redundant analysis.

A unique constraint ensures that duplicate findings (based on rule ID, file path, line number, and description) are not inserted multiple times.

---

### 2. 🔄 SAST Report Ingestion

**Endpoint:** `/api/ingest/sast`  
**Backend Services:** `sast_service.py`, `app.py`

This API endpoint accepts raw JSON reports (e.g., from Semgrep) and extracts key fields from each result. The ingestion logic:

- Parses each entry in the report.
- Extracts rule ID, file path, line number, severity, description, code snippet, and suggested fix.
- Checks for duplicates based on the unique constraint.
- Stores valid, non-duplicate findings into the database.

This enables persistent and structured storage of static analysis results.

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

To ensure consistency, the prompt instructs the model to:

- Be direct, technical, and non-conversational
- Use a fixed Markdown format with the following sections:
  - `### Vulnerability Summary`
  - `### Security Implications`
  - `### Remediation`

This structure allows downstream automation or frontend formatting to remain predictable.

#### LLM Endpoint

- **Endpoint:** `/api/llm/analyze/sast/<finding_id>`
- When triggered, it:
  - Fetches the relevant finding from the database.
  - Generates a structured prompt.
  - Sends it to Ollama’s `/api/generate`.
  - Parses and returns the structured Markdown response.

---

### 4. ⚡ LLM Caching Strategy

To optimize performance and prevent redundant LLM invocations, a database-backed caching mechanism is implemented.

#### How It Works

1. **Prompt Generation**: A consistent prompt is generated for the finding.
2. **Hashing**: A SHA256 hash of the prompt is calculated.
3. **Cache Check**:
   - If a matching `llm_analysis_prompt_hash` exists **and**
   - A valid `llm_analysis_content` is stored,
   - Then the cached content is served immediately.
4. **Cache Miss**:
   - If no match or no analysis content exists,
   - A new LLM request is made and response stored along with the new hash.

#### Benefits

- **Speed**: Frequent requests for the same finding are served instantly.
- **Accuracy**: If any detail in the finding changes, a new hash is generated and fresh analysis is performed.
- **Efficiency**: Reduces unnecessary load on the LLM engine, especially when dealing with large sets of vulnerabilities.

---

### ✅ Summary

| Step               | Description                                                                 |
|--------------------|-----------------------------------------------------------------------------|
| Ingest             | Accept and parse JSON reports, extract and store deduplicated SAST findings |
| Analyze            | Generate a structured prompt and send it to the LLM                         |
| Structure Response | Receive human-readable, Markdown-formatted analysis                        |
| Cache              | Store analysis and hash to prevent duplicate work                           |
| Serve              | Return cached or fresh results on demand                                    |

---

> 🧠 *This SAST+LLM pipeline transforms raw security data into contextual, actionable, and structured intelligence—making triage and remediation significantly faster for developers and security teams.*
