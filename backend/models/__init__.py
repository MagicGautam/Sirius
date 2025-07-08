# backend/__init__.py

import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_caching import Cache
from flask_cors import CORS
import logging

# Initialize extensions outside create_app
db = SQLAlchemy()
cache = Cache()
cors = CORS()

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def create_app():
    app = Flask(__name__)

    # Define the base path for databases
    db_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'databases')

    # Create the databases folder if it doesn't exist
    if not os.path.exists(db_folder):
        os.makedirs(db_folder)
        logger.info(f"Created database folder: {db_folder}")

    # --- Database Configuration with Multiple Binds ---
    app.config['SQLALCHEMY_BINDS'] = {
        'sast_db': f'sqlite:///{os.path.join(db_folder, "sast.db")}',
        'container_db': f'sqlite:///{os.path.join(db_folder, "container.db")}'
        # If you decide to put LLMSummary in its own DB, you'd add:
        # 'llm_db': f'sqlite:///{os.path.join(db_folder, "llm.db")}'
    }
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # Recommended to disable

    # --- Caching Configuration ---
    app.config['CACHE_TYPE'] = 'simple'
    app.config['CACHE_DEFAULT_TIMEOUT'] = 300

    # --- Initialize Extensions ---
    db.init_app(app)
    cache.init_app(app)
    cors.init_app(app)

    # Import models for db.create_all() to discover them
    # Make sure ALL your model files are imported here
    with app.app_context():
        from .models import SASTFinding, LLMSummary # Assuming LLMSummary is here
        from .Container_models import ContainerScan, ContainerFinding, CVERichment # Import your new model file

        # db.create_all() will create tables in all defined binds
        db.create_all()
        logger.info("Database tables created/updated across all binds.")

    # Initialize your services with the db object
    from .services.sast_service import SASTService
    from .services.llm_service import LLMService
    from .services.container_service import ContainerService
    from .services.cve_enrichment_service import CVEEnrichmentService

    app.sast_service = SASTService(db)
    app.llm_service = LLMService(cache) # Pass cache to LLMService
    app.container_service = ContainerService(db) # Initialize new container service
    app.cve_enrichment_service = CVEEnrichmentService(db) # Initialize new CVE enrichment service

    return app