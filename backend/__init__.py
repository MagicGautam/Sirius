import os
from flask import Flask
import logging
from backend.config import DevelopmentConfig
from backend.models import db, cache, cors

logging.basicConfig(level=logging.DEBUG)
logger= logging.getLogger(__name__)



def create_app(config_class):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'databases')

    if not os.path.exists(db_folder):
        os.makedirs(db_folder)
        logger.info(f"Created databases directory at {db_folder}")

    db.init_app(app)
    cache.init_app(app)
    cors.init_app(app)  

    with app.app_context():

        from backend.models.sast_models import SastFinding
        from backend.services.sast_service import SastService
        from backend.services.llm_service import LLMService
        #from backend.services.container_service import ContainerService # Ensure this file exists and class is defined
        #from backend.services.cve_enrichment_service import CVEEnrichmentService # Ensure this file exists and class is defined

    app.sast_service = SastService(db)
    app.llm_service = LLMService(ollama_url="http://localhost:11434", model_name="gemma3:1b")
    app.llm_service = LLMService(cache) # Pass cache to LLMService
    #app.container_service = ContainerService(db) # Initialize new container service
    #app.cve_enrichment_service = CVEEnrichmentService(db) # Initialize new CVE enrichment service

    from .routes import api_bp
    app.register_blueprint(api_bp)

    return app
 
