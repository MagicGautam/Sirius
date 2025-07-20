# backend/__init__.py

import os
from flask import Flask
import logging
from backend.config import DevelopmentConfig

# Define logger early for maximum visibility
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# CRITICAL EARLY IMPORTS:
# Import the Flask-SQLAlchemy 'db' object.
# 'Base' is no longer needed here if models inherit from db.Model.
from backend.models import db, cache, cors 
# You still need to import your models directly here to ensure
# db.metadata (which db.Model uses) discovers them.
from backend.models.sast_models import SastFinding
from backend.models.container_models import ContainerScan, ContainerFinding, CVERichment

# --- NEW DEBUGGING BLOCK: VERY EARLY METADATA INSPECTION ---
# Now we inspect db.metadata.tables directly
logger.debug("--- Early inspection of db.metadata.tables (before app init) ---")
if not db.metadata.tables:
    logger.critical("FATAL: db.metadata.tables is EMPTY before app initialization! "
                    "This means models inheriting from db.Model have not been loaded. "
                    "Check imports in backend/models/__init__.py and backend/__init__.py.")
for table_name, table_obj in db.metadata.tables.items():
    # Flask-SQLAlchemy now correctly sets 'bind_key' in table.info
    bind_key_info = table_obj.info.get('bind_key', '<No Bind Key>')
    logger.debug(f"  Table: {table_name}, Declared Bind Key: {bind_key_info}")
logger.debug("--- Finished early inspection ---")
# --- END NEW DEBUGGING BLOCK ---


def create_app(config_class):
    app = Flask(__name__)
   
    db_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'databases')
    
    # Ensure the databases directory exists
    if not os.path.exists(db_folder):
        os.makedirs(db_folder)
        logger.info(f"Created databases directory at {db_folder}")

    app.config.from_object(config_class)

    # --- DEVELOPMENT MODE ONLY: Delete existing database files ---
    configured_bind_uris = app.config.get('SQLALCHEMY_BINDS', {}).values()
    
    for uri in configured_bind_uris:
        if uri.startswith('sqlite:///'):
            db_file_path = uri.replace('sqlite:///', '')
            if os.path.exists(db_file_path):
                try:
                    os.remove(db_file_path)
                    logger.info(f"DEVELOPMENT MODE: Deleted existing database file: {db_file_path}")
                except OSError as e:
                    logger.error(f"Error deleting database file {db_file_path} on startup: {e}", exc_info=True)
                    logger.warning(f"Failed to delete {db_file_path}. Previous data might persist.")
    # --- END DEVELOPMENT MODE BLOCK ---

    db.init_app(app) # Initialize Flask-SQLAlchemy's db object with the app and its config

    cache.init_app(app)
    cors.init_app(app)  

    with app.app_context():
        # Import services AFTER app context is pushed and db is initialized
        from backend.services.sast_service import SastService
        from backend.services.llm_service import LLMService
        from backend.services.container_service import ContainerService 
        
        logger.info("--- Starting Flask-SQLAlchemy db.create_all() for all configured binds ---")
        try:
            db.create_all() 
            logger.info("Flask-SQLAlchemy db.create_all() completed for all binds.")

            # --- VERIFICATION STEP FOR ALL BINDS (MORE ROBUST) ---
            configured_binds = app.config.get('SQLALCHEMY_BINDS', {})
            for bind_key, bind_uri in configured_binds.items():
                try:
                    engine_for_bind = db.get_engine(app, bind=bind_key)
                    
                    # Force a new connection and inspection
                    with engine_for_bind.connect() as connection:
                        from sqlalchemy import inspect
                        inspector = inspect(connection)
                        tables_in_db = inspector.get_table_names()
                        logger.info(f"Verification: Tables found in '{bind_key}' database (URL: {engine_for_bind.url}): {tables_in_db}")

                        if bind_key == 'sast_db':
                            if 'sast_findings' in tables_in_db:
                                logger.info(f"Verification: 'sast_findings' table CONFIRMED in '{bind_key}' database.")
                            else:
                                logger.critical(f"Verification: 'sast_findings' table CRITICALLY MISSING in '{bind_key}' database after create_all!")
                        elif bind_key == 'container_db':
                            if 'container_scans' in tables_in_db and 'container_findings' in tables_in_db and 'cve_enrichment' in tables_in_db:
                                logger.info(f"Verification: All container tables CONFIRMED in '{bind_key}' database.")
                            else:
                                logger.critical(f"Verification: Some container tables CRITICALLY MISSING in '{bind_key}' database after create_all! Found: {tables_in_db}")
                except Exception as e:
                    logger.error(f"Error during verification for bind '{bind_key}': {e}", exc_info=True)

        except Exception as e:
            logger.critical(f"FATAL ERROR during Flask-SQLAlchemy db.create_all(): {e}", exc_info=True)
            raise 
        logger.info("--- Finished database table creation process ---")
          
    # Initialize LLMService first, as other services depend on it
    app.llm_service = LLMService(ollama_url="http://localhost:11434", model_name="gemma3:1b")
    
    # Initialize other services, passing the db instance (which provides the session) and llm_service instance
    app.sast_service = SastService(db, app.llm_service)
    app.container_service = ContainerService(db, app.llm_service)

    from .routes import api_bp
    app.register_blueprint(api_bp)

    return app