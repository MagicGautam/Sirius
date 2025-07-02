# backend/services/llm_service.py
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
import logging
import json # Import json for string formatting

logger = logging.getLogger(__name__)

class LLMService:
    def __init__(self, model_name="google/gemma-2b-it", device="cuda"):
        self.model = None
        self.tokenizer = None
        self.device = device
        self.model_name = model_name
        self._is_loaded = False

        logger.info(f"Initializing LLMService with model: {self.model_name} on device: {self.device}")
        # Model loading will happen asynchronously or during first use
        # For simplicity, we'll try to load it during init, but Flask might block if it's too slow
        try:
            self._load_model_and_tokenizer()
            self._is_loaded = True
        except RuntimeError as e:
            logger.error(f"LLM model failed to load during initialization: {e}")
            self._is_loaded = False # Mark as not loaded if an error occurs

    def _load_model_and_tokenizer(self):
        # This is a heavy operation, run once
        if self.model and self.tokenizer:
            return

        try:
            logger.info(f"Loading {self.model_name} tokenizer...")
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            logger.info(f"Loading {self.model_name} model...")

            # You might need to adjust torch_dtype or add quantization based on your hardware
            # For CPU, float32 is standard. For GPU, bfloat16 is often preferred if supported.
            self.model = AutoModelForCausalLM.from_pretrained(
                self.model_name,
                torch_dtype=torch.bfloat16 if self.device == "cuda" else torch.float32,
                device_map="auto" if self.device == "cuda" else None, # Let transformers handle device mapping if CUDA
                # low_cpu_mem_usage=True # Can help with CPU memory on some systems
            )

            # If not using device_map="auto", manually move to device for CPU
            if self.device == "cpu" and self.model.device.type != 'cpu': # Check if already on CPU by device_map
                 self.model.to(self.device)

            logger.info(f"Model {self.model_name} and tokenizer loaded successfully.")
            self.model.eval() # Set the model to evaluation mode
            self._is_loaded = True # Mark as loaded

        except Exception as e:
            logger.error(f"Failed to load LLM model or tokenizer: {e}", exc_info=True)
            self.model = None
            self.tokenizer = None
            self._is_loaded = False
            raise RuntimeError(f"Failed to load LLM model: {e}. Ensure you've accepted terms on Hugging Face (google/gemma-2b-it) and run `huggingface-cli login` if needed. Check hardware resources.")

    def is_loaded(self) -> bool:
        return self._is_loaded

    def _generate_sast_prompt(self, sast_finding: dict) -> str:
        # This is where you craft a detailed prompt for SAST findings
        # You can add more fields from the finding as needed
        prompt = f"""Analyze the following SAST vulnerability report. Provide:
1.  A concise summary of the vulnerability.
2.  A clear explanation of its security implications and potential impact.
3.  A specific, actionable, and secure code fix for the provided snippet, explaining the best practices.

Vulnerability Details:
- Rule ID: {sast_finding.get('rule_id', 'N/A')}
- File: {sast_finding.get('file_path', 'N/A')} (Line {sast_finding.get('line_number', 'N/A')})
- Severity: {sast_finding.get('severity', 'N/A')}
- Description: {sast_finding.get('description', 'No description provided.')}
- Code Snippet:
```java
{sast_finding.get('code_snippet', 'No code snippet available.')}