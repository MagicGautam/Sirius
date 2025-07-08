# backend/models/__init__.py

from flask_sqlalchemy import SQLAlchemy
from flask_caching import Cache
from flask_cors import CORS

# Initialize extensions here - these are the objects that will be used globally
# They are NOT yet bound to a specific Flask app instance.
db = SQLAlchemy()
cache = Cache()
cors = CORS()

# You can optionally import your models here if you want them to be discoverable
# directly from 'backend.models'. This isn't strictly necessary for db.create_all()
# if they are imported in the main __init__.py, but can be a pattern for large apps.
# from .sast_models import SastFinding
# from ..Container_models import ContainerScan, ContainerFinding, CVERichment