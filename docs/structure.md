sirius/
└── backend/
    ├── app.py                      # Main Flask app, routes, orchestrates services
    ├── config.py                   # Global configurations
    ├── extensions.py               # NEW FILE: Central SQLAlchemy `db`
    ├── services/                   # Business logic for scan types
    │   └── __init__.py             # 
    │   └── sast_service.py         # SAST (Semgrep) parsing and DB
    ├── models/                     # Database models
    │   └── __init__.py             # Initializing all the DBs here
    |   └── container_models.py     # SQLAlchemy Model for Container Image Findinds
    │   └── sast_models.py          # SQLAlchemy model for SAST findings
    ├── databases/                  # Directory for SQLite .db files
    │   └── sast.db                 # Dedicated SQLite DB for SAST
    │   └── container_db.db         # Dedicated SQLite DB for Container Related 
    |── __init__.py                 # Makes 'backend' a Python package
    |── routes.py                   # Defines routes for REST APIs.
    |── requirements.txt
