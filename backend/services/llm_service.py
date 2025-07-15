import requests
import logging
import json

logger = logging.getLogger(__name__)

class LLMService:
    def __init__(self, ollama_url: str = "http://localhost:11434", model_name: str = "gemma3:1b"):
        self.ollama_url = ollama_url
        self.model_name = model_name
        self._is_loaded = False

        logger.info(f"LLMService Initializing for Ollama at : {self.ollama_url} with model: {self.model_name}")

        try:
            self._test_ollama_connection()
            self._is_loaded= True
            logger.info("Successfully connected to Ollama.")

        except requests.exceptions.ConnectionError:
            logger.critical(f"Failed to connect to Ollama at {self.ollama_url}. "
                            "Please ensure Ollama is running and accessible.")
            self._is_loaded = False
        except Exception as e:
            logger.critical(f"Unexpected error during Ollama connection: {e}")
            self._is_loaded = False


    def _test_ollama_connection(self):
        """Test connection to Ollama server."""
        response = requests.get(f"{self.ollama_url}/api/tags", timeout=5)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        models = response.json().get("models", [])
        if not any(m['name'].startswith(self.model_name.split(':')[0]) for m in models):
             logger.warning(f"Configured model '{self.model_name}' not found in Ollama list. Available models: {[m['name'] for m in models]}")
             # If the model isn't listed, it might still work if it's new, but good to warn
        logger.info(f"Ollama server at {self.ollama_url} is reachable.")

    def is_loaded(self) -> bool:
        """Check if the LLMService is loaded and ready."""
        return self._is_loaded
    
    def _generate_sast_prompt(self, sast_finding: dict ) -> str:
        """
        Generates a detailed prompt for a SAST finding,
        with instructions to keep the output direct and devoid of conversational filler.
        """
        # KEY CHANGES ARE HERE IN THE PROMPT INSTRUCTIONS
        prompt = f"""Analyze the following SAST vulnerability report. Provide only the requested information.
        DO NOT include any conversational phrases, introductory remarks, or concluding statements.
        Be direct, concise, and technical.

        Your response should be structured strictly using the following Markdown headings:

        ### Vulnerability Summary
        [Provide a concise, technical summary of the vulnerability.]

        ### Security Implications
        [Explain the clear security implications and potential impact if exploited.]

        ### Remediation
        [Provide a specific, actionable, and secure code fix for the provided snippet, adhering to best practices and explaining the changes. Also include relevant preventative measures beyond the code fix.]

        Vulnerability Details:
        - Rule ID: {sast_finding.get('rule_id', 'N/A')}
        - File: {sast_finding.get('file_path', 'N/A')} (Line {sast_finding.get('line_number', 'N/A')})
        - Severity: {sast_finding.get('severity', 'N/A')}
        - Description: {sast_finding.get('description', 'No description provided by scanner.')}
        - Code Snippet:```java {sast_finding.get('code_snippet', 'No code snippet available.')}
        - Scanner's Suggested Fix: {sast_finding.get('scanner_suggested_fix', 'No suggested fix provided.')}
        - Analysis (start yourreponse here):"""
        return prompt
    
    def _generate_container_prompt(self, container_finding: dict) -> str:
        """
        Generates a detailed prompt for a Container vulnerability report,
        with instructions to keep the output direct and devoid of conversational filler.
        """
        prompt = f"""Analyze the following Container vulnerability report. Provide only the requested information.
        DO NOT include any conversational phrases, introductory remarks, or concluding statements.
        Be direct, concise, and technical.

        Your response should be structured strictly using the following Markdown headings:

        ### Vulnerability Summary
        [Provide a concise, technical summary of the vulnerability.]

        ### Security Implications
        [Explain the clear security implications and potential impact if exploited.]

        ### Remediation
        [Provide specific, actionable steps to remediate this container vulnerability. This may involve upgrading packages, using a different base image, or applying configuration changes.]

        Vulnerability Details:
        - Vulnerability ID: {container_finding.get('vulnerability_id', 'N/A')}
        - Package Name: {container_finding.get('pkg_name', 'N/A')}
        - Installed Version: {container_finding.get('installed_version', 'N/A')}
        - Fixed Version: {container_finding.get('fixed_version', 'None Available')}
        - Severity: {container_finding.get('severity', 'N/A')}
        - Title: {container_finding.get('title', 'No title provided by scanner.')}
        - Description: {container_finding.get('description', 'No description provided by scanner.')}
        - Primary URL: {container_finding.get('primary_url', 'N/A')}
        - CVSS v3 Score: {container_finding.get('cvss_nvd_v3_score', 'N/A')} (Vector: {container_finding.get('cvss_nvd_v3_vector', 'N/A')})
        - CVSS v2 Score: {container_finding.get('cvss_nvd_v2_score', 'N/A')} (Vector: {container_finding.get('cvss_nvd_v2_vector', 'N/A')})
        - Published Date: {container_finding.get('published_date', 'N/A')}
        - Last Modified Date: {container_finding.get('last_modified_date', 'N/A')}
        - Associated Scan ID: {container_finding.get('scan_id', 'N/A')}
        - Analysis (start yourreponse here):"""
        return prompt
    

    def generate_prompt(self, scan_type: str, finding_data: dict) -> str:
        """ Dispatches to the appropriate prompt generation method based on scan_type."""
        if scan_type == "sast":
            return self._generate_sast_prompt(finding_data)
        elif scan_type == "container":
            return self._generate_container_prompt(finding_data)
        elif scan_type == "dast":
            logger.warning("DAST prompt generation not fully implemented yet.")
            return f"Analyze this DAST finding: {json.dumps(finding_data, indent=2)}"
        elif scan_type == "sca":
            logger.warning("SCA prompt generation not fully implemented yet.")
            return f"Analyze this SCA finding: {json.dumps(finding_data, indent=2)}"
        else:
            raise ValueError(f"Unsupported scan type for LLM analysis: {scan_type}")

    def _parse_llm_output(self, llm_raw_output: str) -> dict:
        """
        Parses the raw LLM output string to extract structured information
        based on the predefined Markdown headings.
        """
        parsed_data = {
            'summary': "No summary generated.",
            'recommendations': "No recommendations generated.",
            'risk_score': None # Will try to extract a number later
        }

        # Regex patterns to find sections based on Markdown headings
        summary_match = re.search(r'### Vulnerability Summary\s*(.*?)(?=\n###|\Z)', llm_raw_output, re.DOTALL)
        if summary_match:
            parsed_data['summary'] = summary_match.group(1).strip()

        recommendations_match = re.search(r'### Remediation\s*(.*?)(?=\n###|\Z)', llm_raw_output, re.DOTALL)
        if recommendations_match:
            parsed_data['recommendations'] = recommendations_match.group(1).strip()
            
        # Optional: Extract a risk score if you want to include it in the LLM's output
        # You'll need to update your prompt to explicitly ask for a risk score
        # For now, we'll keep it simple and expect it later if the prompt is modified.
        # Example if prompt includes "### Risk Score: [1-10]"
        # risk_score_match = re.search(r'### Risk Score:\s*(\d+(\.\d+)?)(?=\n|\Z)', llm_raw_output)
        # if risk_score_match:
        #     try:
        #         parsed_data['risk_score'] = float(risk_score_match.group(1))
        #     except ValueError:
        #         logger.warning(f"Could not parse risk score: {risk_score_match.group(1)}")


        return parsed_data
    
    
    def _parse_llm_output(self, llm_raw_output: str) -> dict:
        """
        Parses the raw LLM output string to extract structured information
        based on the predefined Markdown headings.
        """
        parsed_data = {
            'summary': "No summary generated.",
            'recommendations': "No recommendations generated.",
            'risk_score': None # Will try to extract a number later
        }

        # Regex patterns to find sections based on Markdown headings
        summary_match = re.search(r'### Vulnerability Summary\s*(.*?)(?=\n###|\Z)', llm_raw_output, re.DOTALL)
        if summary_match:
            parsed_data['summary'] = summary_match.group(1).strip()

        recommendations_match = re.search(r'### Remediation\s*(.*?)(?=\n###|\Z)', llm_raw_output, re.DOTALL)
        if recommendations_match:
            parsed_data['recommendations'] = recommendations_match.group(1).strip()
            
        # Optional: Extract a risk score if you want to include it in the LLM's output
        # You'll need to update your prompt to explicitly ask for a risk score
        # For now, we'll keep it simple and expect it later if the prompt is modified.
        # Example if prompt includes "### Risk Score: [1-10]"
        # risk_score_match = re.search(r'### Risk Score:\s*(\d+(\.\d+)?)(?=\n|\Z)', llm_raw_output)
        # if risk_score_match:
        #     try:
        #         parsed_data['risk_score'] = float(risk_score_match.group(1))
        #     except ValueError:
        #         logger.warning(f"Could not parse risk score: {risk_score_match.group(1)}")


        return parsed_data            