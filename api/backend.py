try:
    import werkzeug_patch
except ImportError:
    pass

from flask import Flask, request, jsonify
from pymongo import MongoClient
import base64
import os
import datetime

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
    # Return as binary
    return base64_bytes

@app.route('/')
def index():
    return jsonify({"message": "hello you arent supposed to be here"}), 200

# Registration route
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    
    # Check if required fields are provided
    if not data or 'Username' not in data or 'Password' not in data:
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

# New route: Verify login
@app.route('/api/verifylogin', methods=['POST'])
def verify_login():
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
        return jsonify({"message": "Credentials verified", "verified": True}), 200
    else:
        return jsonify({"error": "Invalid credentials", "verified": False}), 401

# New route: Create application
@app.route('/api/createapplication', methods=['POST'])
def create_application():
    data = request.get_json()
    
    # Check if required fields are provided
    if not data or 'name' not in data or 'description' not in data:
        return jsonify({"error": "Name and description are required"}), 400
    
    name = data['name']
    description = data['description']
    
    # Create application document
    application = {
        "name": name,
        "description": description,
        "created_at": datetime.datetime.utcnow()  # Add timestamp
    }
    
    # Insert application into database
    result = applications_collection.insert_one(application)
    
    return jsonify({
        "message": "Application created successfully", 
        "id": str(result.inserted_id)
    }), 201

# New route: Get applications
@app.route('/api/getapplication', methods=['POST'])
def get_application():
    data = request.get_json()
    
    # Check if required fields are provided
    if not data or 'Username' not in data or 'Password' not in data:
        return jsonify({"error": "Username and Password are required"}), 400
    
    username = data['Username']
    password = data['Password']
    
    # Verify user credentials first
    encoded_password = encode_password(password)
    user = users_collection.find_one({"Username": username})
    
    if not user or user['Password'] != encoded_password:
        return jsonify({"error": "Invalid credentials"}), 401
    
    # If authenticated, retrieve all applications
    applications = list(applications_collection.find({}, {"_id": 0}))
    
    return jsonify({
        "message": "Applications retrieved successfully",
        "applications": applications
    }), 200

if __name__ == '__main__':
    app.run(debug=True)