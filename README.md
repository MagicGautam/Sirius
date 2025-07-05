# DevSecOps Dashboard

## Overview

The DevSecOps Dashboard is a backend application designed to ingest security vulnerability reports (starting with SAST) and leverage a local Large Language Model (LLM) for intelligent analysis and remediation suggestions. It aims to provide developers and security teams with clear, actionable insights directly from raw scanner outputs.

## Features

* **SAST Report Ingestion:** Supports ingesting vulnerability findings from SAST (Static Application Security Testing) tools (e.g., Semgrep-like JSON format).
* **LLM-Powered Vulnerability Analysis:** Integrates with a local LLM (Gemma-3b via Ollama) to provide:
    * Concise technical summaries of vulnerabilities.
    * Clear explanations of security implications and potential impact.
    * Specific, actionable, and secure code fixes.
    * General preventative measures.
* **Intelligent Caching:** Stores LLM analysis results in the database. Subsequent requests for the same finding (with the same underlying prompt data) are served from the cache, significantly speeding up response times and reducing redundant LLM calls.
* **RESTful API:** Provides a clean API for ingesting data and triggering LLM analysis.

## Technologies Used

* **Python 3.10+**
* **Flask:** Web framework for building the backend API.
* **Flask-SQLAlchemy:** ORM (Object Relational Mapper) for database interactions.
* **SQLite:** Lightweight, file-based database for development and local storage.
* **Ollama:** A powerful tool to run large language models locally.
* **Gemma-3b:** The specific LLM used for analysis (downloaded via Ollama).
* **`requests`:** Python library for making HTTP requests to the Ollama server.
* **`hashlib`:** Python's standard library for generating hashes (used for caching logic).

## Setup and Installation

Follow other documentation in /backend/docs/ folder to get started.
