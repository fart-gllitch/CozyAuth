# Import the patch first
try:
    import werkzeug_patch
except ImportError:
    pass
# Standard imports
from flask import Flask, request, jsonify
import json
import os
import datetime
import sys
# Add parent directory to path so we can import from backend.py
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# Import your app
from api import backend
app = backend.app

# CORS handling for all responses
@app.after_request
def add_cors_headers(response):
    origin = request.headers.get('Origin')
    allowed_origins = ['https://cozy-auth.vercel.app/', 'https://cozy-auth.vercel.app/']
    
    if origin in allowed_origins:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version, X-API-Key, Authorization'
        
    # Some routes like health checks or static files might not need CORS
    return response

# Handle OPTIONS at the root level
@app.route('/', methods=['OPTIONS'])
@app.route('/<path:path>', methods=['OPTIONS'])
def options_handler(path=''):
    response = app.make_default_options_response()
    origin = request.headers.get('Origin')
    allowed_origins = ['https://cozy-auth.vercel.app/', 'https://cozy-auth.vercel.app/']
    
    if origin in allowed_origins:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version, X-API-Key, Authorization'
    
    return response

# This is the format Vercel expects
flask_app = app  # Assign your app to flask_app