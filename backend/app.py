# backend/app.py

# backend/app.py
from backend import create_app # Importing the create_app function
from backend.config import DevelopmentConfig  #Importing the configuration class
import logging

# Configure basic logging for the entry point if needed
logging.basicConfig(level=logging.DEBUG)
logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO) # Log SQL statements at INFO level

# Create the Flask application instance using the factory
app = create_app(DevelopmentConfig)

if __name__ == '__main__':
    # This block only runs when app.py is executed directly
    app.run(debug=True, port=8000) # Run the Flask app on port 8000 with debug mode enabled.
    # You can access the API at http://localhost:8000/api/ingest/sast
    # and http://localhost:8000/api/findings/sast to retrieve SAST findings.