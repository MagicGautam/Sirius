# SIRIUS - Directory Structure

sirius/
└── backend/
    ├── app.py                      # Main Flask app, orchestrates services and blueprints
    ├── config.py                   # Global configurations for Flask and extensions
    ├── extensions.py               # NEW FILE: Centralizes Flask extensions (SQLAlchemy, Cache, CORS)
    ├── services/                   # Business logic layer for scan types
    │   ├── __init__.py             # Makes 'services' a Python package
    │   ├── container_service.py    # NEW: Business logic for container scan ingestion and retrieval
    │   ├── llm_service.py          # NEW: Logic for LLM interaction, prompting, and parsing
    │   └── sast_service.py         # Business logic for SAST (Semgrep) parsing and retrieval
    ├── models/                     # Database models for ORM
    │   ├── __init__.py             # Makes 'models' a Python package; loads all model definitions
    │   ├── container_models.py     # NEW: SQLAlchemy models for Container findings and scans
    │   └── sast_models.py          # SQLAlchemy models for SAST findings and scans
    ├── databases/                  # Directory for SQLite .db files
    │   ├── sast.db                 # Dedicated SQLite DB for SAST
    │   └── container.db         # Dedicated SQLite DB for Container related data
    ├── __init__.py                 # Initializes the Flask app, extensions, and database
    ├── routes.py                   # Defines routes and registers API blueprints
    └── requirements.txt            # Project dependencies