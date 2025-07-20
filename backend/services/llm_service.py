# backend/services/llm_service.py

import requests
import logging
import json
import re   # Needed for regular expressions in _parse_llm_output
import ollama # Needed for ollama.Client and ollama.generate
from typing import Dict, Any # For type hinting

logger = logging.getLogger(__name__)

class LLMService:
    def __init__(self, ollama_url: str = "http://localhost:11434", model_name: str = "gemma3:1b"):
        self.ollama_url = ollama_url
        self.model_name = model_name
        self._is_loaded = False
        self.client = None 

        logger.info(f"LLMService Initializing for Ollama at : {self.ollama_url} with model: {self.model_name}")

        try:
            self.client = ollama.Client(host=self.ollama_url) 
            self._test_ollama_connection() 
            self._is_loaded= True
            logger.info("Successfully connected to Ollama.")

        except ollama.ResponseError as e: 
            logger.critical(f"Failed to connect to Ollama at {self.ollama_url} or list models: {e}")
            self._is_loaded = False
        except Exception as e:
            logger.critical(f"Unexpected error during Ollama client setup: {e}", exc_info=True)
            self._is_loaded = False


    def _test_ollama_connection(self):
        """Test connection to Ollama server using the instantiated client."""
        models_response = self.client.list()
        # Safely get the 'models' list; if 'models' key is missing, defaults to empty list
        models = models_response.get('models', []) 

        # NEW: Add checks for dictionary type and existence of 'name' key
        if not any(isinstance(m, dict) and 'name' in m and m['name'].startswith(self.model_name.split(':')[0]) for m in models):
             # For logging, also use .get('name', 'N/A') for robustness
             logger.warning(f"Configured model '{self.model_name}' not found in Ollama list. Available models: {[m.get('name', 'N/A') for m in models if isinstance(m, dict)]}")
        logger.info(f"Ollama server at {self.ollama_url} is reachable.")

    def is_loaded(self) -> bool:
        """Check if the LLMService is loaded and ready."""
        return self._is_loaded
    
    def _generate_sast_prompt(self, sast_finding: dict ) -> str:
        """
        Generates a detailed prompt for a SAST finding,
        with instructions to keep the output direct and devoid of conversational filler.
        """
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

        ### Risk Score
        [Assign a numerical risk score from 0.0 to 10.0, e.g., 7.5. Consider severity, exploitability, and potential impact.]

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

        ### Risk Score
        [Assign a numerical risk score from 0.0 to 10.0, e.g., 7.5. Consider severity, exploitability, and potential impact.]

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
            'risk_score': None
        }

        # Regex patterns to find sections based on Markdown headings as defined in YOUR prompts
        summary_match = re.search(r'### Vulnerability Summary\s*(.*?)(?=\n###|\Z)', llm_raw_output, re.DOTALL)
        if summary_match:
            parsed_data['summary'] = summary_match.group(1).strip()

        # Your prompt uses "### Remediation" for recommendations
        recommendations_match = re.search(r'### Remediation\s*(.*?)(?=\n###|\Z)', llm_raw_output, re.DOTALL)
        if recommendations_match:
            parsed_data['recommendations'] = recommendations_match.group(1).strip()
            
        # Extract Risk Score: This regex matches '### Risk Score' followed by a number
        # IMPORTANT: Ensure your prompts NOW include a "### Risk Score" section
        risk_score_match = re.search(r'### Risk Score\s*([\d.]+)', llm_raw_output)
        if risk_score_match:
            try:
                parsed_data['risk_score'] = float(risk_score_match.group(1).strip())
            except ValueError:
                logger.warning(f"Could not parse risk score: '{risk_score_match.group(1)}'")
                parsed_data['risk_score'] = None

        return parsed_data
    
    def generate_analysis(self, prompt: str) -> Dict[str, Any]:
        """
        Sends the prompt to Ollama's /api/generate endpoint and returns the parsed LLM analysis data.
        """
        if not self.is_loaded() or self.client is None: # Added check for self.client
            logger.error("LLM service is not loaded or Ollama client not initialized, cannot generate analysis.")
            raise RuntimeError("LLM service is not ready. Ollama connection failed or client not initialized.")

        try:
            # Use self.client.generate()
            response = self.client.generate(
                model=self.model_name,
                prompt=prompt,
                stream=False, # We want the full response at once
                options={'temperature': 0.1} # Lower temperature for more consistent output
            )
            
            raw_llm_output = response.get('response', '').strip()
            
            if not raw_llm_output:
                logger.warning("Ollama returned an empty response for model %s. Returning default parsed data.", self.model_name)
                return {
                    "summary": "LLM returned an empty response.",
                    "recommendations": "No recommendations available.",
                    "risk_score": None
                }
            
            parsed_analysis = self._parse_llm_output(raw_llm_output)
            return parsed_analysis

        except ollama.ResponseError as e:
            logger.error(f"Ollama API error during generate for model {self.model_name}: {e}")
            if "model not found" in str(e).lower():
                logger.error(f"Please ensure model '{self.model_name}' is downloaded. Run: ollama pull {self.model_name}")
            raise RuntimeError(f"Failed to get response from Ollama: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during LLM analysis generation: {e}", exc_info=True)
            raise RuntimeError(f"An unexpected error occurred during LLM analysis generation: {e}")