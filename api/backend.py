try:
    import werkzeug_patch
except ImportError:
    pass

from flask import Flask, request, jsonify
from pymongo import MongoClient
import base64
import os
import datetime
import random

app = Flask(__name__)

# MongoDB connection
mongo_uri = "mongodb+srv://CozyAdmin:cozypassword@euphorixcluster.hpirebe.mongodb.net/?retryWrites=true&w=majority&appName=EuphorixCluster"
client = MongoClient(mongo_uri)
db = client["CozyDatabase"]
users_collection = db["RegisteredUsers"]
applications_collection = db["Applications"]  # New collection for applications

# Encode password: base64 then convert to binary
def encode_password(password):
    # Convert password to base64
    base64_bytes = base64.b64encode(password.encode('utf-8'))
    # Return as string
    return base64_bytes.decode('utf-8')

# Generate unique 5-digit app ID
def generate_app_id():
    while True:
        # Generate random 5-digit number
        app_id = str(random.randint(10000, 99999))
        
        # Check if this ID already exists in the database
        existing_app = applications_collection.find_one({"app_id": app_id})
        if not existing_app:
            return app_id

@app.route('/')
def index():
    return jsonify({"message": "hello you arent supposed to be here"}), 200

# Registration route
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    
    # Check if required fields are provided
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"error": "Username and Password are required"}), 400
    
    username = data['Username']
    password = data['Password']
    
    # Check if user already exists
    existing_user = users_collection.find_one({"Username": username})
    if existing_user:
        return jsonify({"error": "Username already exists"}), 409
    
    # Encode password
    encoded_password = encode_password(password)
    
    # Create user document
    user = {
        "Username": username,
        "Password": encoded_password
    }
    
    # Insert user into database
    result = users_collection.insert_one(user)
    
    return jsonify({"message": "User registered successfully", "id": str(result.inserted_id)}), 201
 
# Login route
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    
    # Check if required fields are provided
    if not data or 'Username' not in data or 'Password' not in data:
        return jsonify({"error": "Username and Password are required"}), 400
    
    username = data['Username']
    password = data['Password']
    
    # Encode the provided password for comparison
    encoded_password = encode_password(password)
    
    # Find user in database
    user = users_collection.find_one({"Username": username})
    
    if not user:
        return jsonify({"error": "Invalid credentials"}), 401
    
    # Compare passwords
    if user['Password'] == encoded_password:
        return jsonify({"message": "Login successful", "username": username}), 200
    else:
        return jsonify({"error": "Invalid credentials"}), 401



# New route: Create application
@app.route('/api/createapplication', methods=['POST'])
def create_application():
    data = request.get_json()
    
    # Check if required fields are provided
    if not data or 'name' not in data or 'description' not in data:
        return jsonify({"error": "Name and description are required"}), 400
    
    name = data['name']
    description = data['description']
    
    # Generate a unique 5-digit app ID
    app_id = generate_app_id()
    
    # Create application document
    application = {
        "app_id": app_id,
        "name": name,
        "description": description,
        "created_at": datetime.datetime.utcnow()  # Add timestamp
    }
    
    # Insert application into database
    result = applications_collection.insert_one(application)
    
    return jsonify({
        "message": "Application created successfully", 
        "id": str(result.inserted_id),
        "app_id": app_id
    }), 201

@app.route('/api/getapplications', methods=['GET', 'POST'])
def get_applications():
    # Get authorization header
    auth_header = request.headers.get('Authorization')
    
    # Check if Authorization header is provided
    if not auth_header or not auth_header.startswith('Basic '):
        return jsonify({"error": "Authorization required"}), 401
    
    # Extract and decode credentials from Basic auth
    try:
        encoded_credentials = auth_header.split(' ')[1]
        decoded_credentials = base64.b64decode(encoded_credentials).decode('utf-8')
        username, password = decoded_credentials.split(':')
    except Exception:
        return jsonify({"error": "Invalid authorization format"}), 401
    
    # Encode the provided password for comparison
    encoded_password = encode_password(password)
    
    # Find user in database
    user = users_collection.find_one({"Username": username})
    
    # Validate credentials
    if not user:
        return jsonify({"error": "User not found"}), 401
    
    if user['Password'] != encoded_password:
        return jsonify({"error": "Invalid credentials"}), 401
    
    # Check if app_id was provided in either GET or POST request
    app_id = None
    
    if request.method == 'GET':
        app_id = request.args.get('app_id')
    elif request.method == 'POST':
        data = request.get_json()
        app_id = data.get('app_id') if data else None
    
    # If app_id is provided, find that specific application
    if app_id:
        application = applications_collection.find_one({"app_id": app_id}, {"_id": 0})
        if not application:
            return jsonify({"error": f"Application with ID {app_id} not found"}), 404
        
        return jsonify({
            "message": "Application retrieved successfully",
            "application": application
        }), 200
    else:
        # If no app_id, retrieve all applications
        applications = list(applications_collection.find({}, {"_id": 0}))
        
        return jsonify({
            "message": "Applications retrieved successfully",
            "applications": applications
        }), 200

if __name__ == '__main__':
    app.run(debug=True)