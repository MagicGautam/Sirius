# Sirius 

## Overview

Sirius is a Security Dashboard designed to ingest security vulnerability reports from various scanners (including SAST and Container), and leverage a local Large Language Model (LLM) for intelligent analysis and remediation suggestions. It aims to provide developers and security teams with clear, actionable insights directly from raw scanner outputs, transforming data into intelligence.

Note: Since no real-world situations are being simulated currently, reports are used from the Defect Dojo JSON report database. Defect Dojo is a widely adopted vulnerability management system. For more information, refer to the official GitHub repository: https://github.com/DefectDojo/django-DefectDojo

## Features

* **SAST Report Ingestion:** Supports ingesting vulnerability findings from SAST (Static Application Security Testing) tools (e.g., Semgrep-like JSON format). The ingestion process now creates a parent scan record, linking all findings to it.
* **Container Scan Support:** New feature that supports ingesting vulnerability reports from tools like Trivy. It also utilizes a parent-child data model, linking findings to a specific container image scan.
* **LLM-Powered Vulnerability Analysis:** Integrates with a local LLM (Gemma-3b via Ollama) to provide human-readable analysis for both SAST and container findings, including:
    * Concise technical summaries of vulnerabilities.
    * Clear explanations of security implications and potential impact.
    * Specific, actionable, and secure code fixes.
    * General preventative measures and a risk score.
* **Intelligent Caching:** Stores LLM analysis results in the database with a unique prompt hash. Subsequent requests for the same finding (with the same underlying prompt data) are served from the cache, significantly speeding up response times and reducing redundant LLM calls.
* **RESTful API:** Provides a clean and more robust RESTful API for ingesting data and triggering LLM analysis for both SAST and container scan types.

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

Follow the documentation in the `/docs` folder to get started. A basic setup involves:

1.  Clone the repository: `git clone <repository-url>`
2.  Navigate to the `backend` folder and set up a virtual environment: `python -m venv venv`
3.  Activate the virtual environment: `source venv/bin/activate` (or `venv\Scripts\activate` on Windows)
4.  Install dependencies: `pip install -r requirements.txt`
5.  Install and run Ollama with the Gemma model.
6.  Run the Flask app: `flask run`

This [Ollama tutorial](https://www.youtube.com/watch?v=UtSSMs6ObqY) provides a quick guide to getting started with Ollama and running local LLMs.
http://googleusercontent.com/youtube_content/0
