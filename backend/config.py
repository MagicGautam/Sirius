# backend/config.py
import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_DIR = os.path.join(BASE_DIR, 'databases')
os.makedirs(DB_DIR, exist_ok=True) # Ensure the databases directory exists

class Config:
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'  # Default to in-memory for base config

class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_BINDS = {
        'sast_db': f'sqlite:///{os.path.join(DB_DIR, "sast.db")}',
        # 'sca_db': f'sqlite:///{os.path.join(DB_DIR, "sca.db")}',
        'container_db': f'sqlite:///{os.path.join(DB_DIR, "container.db")}'
        # 'dast_db': f'sqlite:///{os.path.join(DB_DIR, "dast.db")}'
    }
# You can add ProductionConfig, TestingConfig later