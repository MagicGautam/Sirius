sirius/
└── backend/
    ├── app.py                      # Main Flask app, routes, orchestrates services
    ├── config.py                   # Global configurations
    ├── extensions.py               # NEW FILE: Central SQLAlchemy `db` object
    ├── services/                   # Business logic for scan types
    │   └── __init__.py
    │   └── sast_service.py         # SAST (Semgrep) parsing and DB interactions
    ├── models/                     # Database models
    │   └── __init__.py
    │   └── sast_models.py          # SQLAlchemy model for SAST findings
    ├── databases/                  # Directory for SQLite .db files
    │   └── sast.db                 # Dedicated SQLite DB for SAST
    └── __init__.py                 # Makes 'backend' a Python package
    └── requirements.txt
