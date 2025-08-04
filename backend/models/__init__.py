# backend/models/__init__.py

from flask_sqlalchemy import SQLAlchemy
from flask_caching import Cache
from flask_cors import CORS

# Initialize extensions here
# db instance will now automatically manage metadata for models inheriting from db.Model
db = SQLAlchemy() 
cache = Cache()
cors = CORS()

# IMPORTANT: REMOVE the following two lines if they exist:
# from sqlalchemy.ext.declarative import declarative_base
# Base = declarative_base()

# Also REMOVE the manual loop that attempted to set bind_key in table.info:
# for mapper in Base.registry.mappers:
#     cls = mapper.class_
#     if hasattr(cls, '__bind_key__') and cls.__table__ is not None:
#         cls.__table__.info['bind_key'] = cls.__bind_key__

# You MUST import your model classes here.
# This ensures that Flask-SQLAlchemy's `db.metadata` discovers them
# when they inherit from `db.Model`.
from .sast_models import SastScan, SastFinding
from .container_models import ContainerScan, ContainerFinding, CVERichment