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
        Generates a detailed prompt for a SAST finding.
        """
        prompt = f"""You are a highly skilled cybersecurity analyst. Analyze the following SAST vulnerability report. Provide:
        1.  A concise, technical summary of the vulnerability (e.g., "SQL Injection in 'login' function").
        2.  A clear explanation of its security implications and potential impact if exploited (e.g., "An attacker could bypass authentication...").
        3.  A specific, actionable, and secure code fix for the provided snippet, adhering to best practices and explaining the changes.
        4.  Briefly mention preventative measures beyond the code fix, if applicable.

        Vulnerability Details:
        - Rule ID: {sast_finding.get('rule_id', 'N/A')}
        - File: {sast_finding.get('file_path', 'N/A')} (Line {sast_finding.get('line_number', 'N/A')})
        - Severity: {sast_finding.get('severity', 'N/A')}
        - Description: {sast_finding.get('description', 'No description provided by scanner.')}
        - Code Snippet:```java {sast_finding.get('code_snippet', 'No code snippet available.')}
        - Scanner's Suggested Fix: {sast_finding.get('scanner_suggested_fix', 'No suggested fix provided.')}
        - Analysis (start yourreponse here):"""
        return prompt
    

    def generate_prompt(self, scan_type: str, finding_data: dict) -> str:
        """ Dispatches to the appropriate prompt generation method based on scan_type."""
        if scan_type == "sast":
            return self._generate_sast_prompt(finding_data)
        elif scan_type == "dast":
            logger.warning("DAST prompt generation not fully implemented yet.")
            return f"Analyze this DAST finding: {json.dumps(finding_data, indent=2)}"
        elif scan_type == "sca":
            logger.warning("SCA prompt generation not fully implemented yet.")
            return f"Analyze this SCA finding: {json.dumps(finding_data, indent=2)}"
        else:
            raise ValueError(f"Unsupported scan type for LLM analysis: {scan_type}")

    def generate_analysis(self, prompt_text: str, max_tokens: int = 700) -> str:
        """
        Generates an LLM-based analysis using the Ollama API.
        Args:
            prompt_text (str): The crafted prompt for the LLM.
            max_tokens (int): The maximum number of tokens to generate.
        Returns:
            str: The LLM's generated analysis.
        """
        if not self.is_loaded():
            logger.error("Ollama connection not established. Cannot generate analysis.")
            return "Error: LLM service is not ready. Please ensure Ollama is running."

        # Ollama API endpoint for generation
        generate_url = f"{self.ollama_url}/api/generate"
        
        # Parameters for Ollama API
        payload = {
            "model": self.model_name,
            "prompt": prompt_text,
            "stream": False,  # We want the full response at once
            "options": {
                "num_predict": max_tokens, # Max tokens to generate
                "temperature": 0.7,
                "top_k": 50,
                "top_p": 0.95,
                # "repeat_penalty": 1.1 # Optional: Can help prevent repetition
            }
        }

        logger.info(f"Sending request to Ollama for analysis (model: {self.model_name}, prompt_len: {len(prompt_text)}).")
        try:
            response = requests.post(generate_url, json=payload, timeout=300) # 5 minute timeout
            response.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)
            
            result = response.json()
            # Ollama's /api/generate returns a 'response' field with the generated text
            llm_output = result.get('response', '').strip()

            # Ollama models don't typically repeat the prompt like HuggingFace Transformers directly
            # but if it does, this ensures it's removed.
            if llm_output.startswith(prompt_text):
                llm_output = llm_output[len(prompt_text):].strip()

            logger.info("Ollama analysis generated successfully.")
            return llm_output
        except requests.exceptions.Timeout:
            logger.error("Ollama generation request timed out.")
            return "Error: LLM generation timed out. Ollama took too long to respond."
        except requests.exceptions.RequestException as e:
            logger.error(f"Error communicating with Ollama: {e}", exc_info=True)
            return f"Error connecting to Ollama: {e}. Check if Ollama server is running."
        except json.JSONDecodeError:
            logger.error("Failed to decode JSON response from Ollama.", exc_info=True)
            return "Error: Invalid JSON response from Ollama."
        except Exception as e:
            logger.error(f"An unexpected error occurred during Ollama generation: {e}", exc_info=True)
            return f"Error during LLM analysis: {e}. Check server logs."
            