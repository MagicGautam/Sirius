# backend/config.py
import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_DIR = os.path.join(BASE_DIR, 'databases')
os.makedirs(DB_DIR, exist_ok=True) # Ensure the databases directory exists

class Config:
    SQLALCHEMY_TRACK_MODIFICATIONS = False

class DevelopmentConfig(Config):
    DEBUG = True
    SAST_DATABASE_URI = f'sqlite:///{os.path.join(DB_DIR, "sast.db")}'
    # SCA_DATABASE_URI = f'sqlite:///{os.path.join(DB_DIR, "sca.db")}'
    # CONTAINER_DATABASE_URI = f'sqlite:///{os.path.join(DB_DIR, "container.db")}'
    # DAST_DATABASE_URI = f'sqlite:///{os.path.join(DB_DIR, "dast.db")}'

# You can add ProductionConfig, TestingConfig later