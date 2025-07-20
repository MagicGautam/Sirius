# backend/config.py
import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_DIR = os.path.join(BASE_DIR, 'databases')
os.makedirs(DB_DIR, exist_ok=True) # Ensure the databases directory exists

class Config:
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # No default SQLALCHEMY_DATABASE_URI needed if all models use binds.
    # If you have any models *without* a __bind_key__, they would go into this default URI.
    # For now, keeping it as in-memory as you had it.
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'  

    # Caching configuration (keeping as before)
    CACHE_TYPE = 'SimpleCache'
    CACHE_DEFAULT_TIMEOUT = 300

class DevelopmentConfig(Config):
    DEBUG = True
    # Defined specific paths for SAST and Container databases using binds
    SQLALCHEMY_BINDS = {
        'sast_db': f'sqlite:///{os.path.join(DB_DIR, "sast.db")}',
        'container_db': f'sqlite:///{os.path.join(DB_DIR, "container.db")}'
    }

# You can add ProductionConfig, TestingConfig later