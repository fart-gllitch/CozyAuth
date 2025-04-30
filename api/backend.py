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
import hashlib
import time
import uuid

app = Flask(__name__)

# MongoDB connection
mongo_uri = "mongodb+srv://CozyAdmin:cozypassword@euphorixcluster.hpirebe.mongodb.net/?retryWrites=true&w=majority&appName=EuphorixCluster"
client = MongoClient(mongo_uri)
db = client["CozyDatabase"]
users_collection = db["RegisteredUsers"]
applications_collection = db["Applications"]  # Collection for applications
keys_collection = db["Keys"]  # Collection for keys

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

# Generate unique API key
def generate_api_key():
    # Generate a unique key based on UUID and current timestamp
    unique_string = f"{uuid.uuid4()}-{time.time()}"
    # Hash the string to create a consistent format
    hashed = hashlib.sha256(unique_string.encode()).hexdigest()
    # Return the first 32 characters as the API key
    return hashed[:32]

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
        "Password": encoded_password,
        "api_keys": []  # Initialize empty api_keys array
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

# Create application route
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

# Get applications route
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

# Route to retrieve API key for a user and app
@app.route('/api/retrieveapikey', methods=['POST'])
def retrieve_api_key():
    data = request.get_json()
    
    # Check if required fields are provided
    if not data or 'appId' not in data or 'username' not in data:
        return jsonify({"error": "App ID and username are required"}), 400
    
    app_id = data['appId']
    username = data['username']
    limit = data.get('limit', 5)  # Default to 5 if not provided
    page = data.get('page', 1)  # Default to page 1 if not provided
    
    # Find user in database
    user = users_collection.find_one({"Username": username})
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # Check if the user has the api_keys field
    if 'api_keys' not in user:
        # Initialize empty api_keys field for user
        users_collection.update_one(
            {"Username": username},
            {"$set": {"api_keys": []}}
        )
        return jsonify({"message": "No API keys found for this user"}), 404
    
    # Find the specific API key for the given app ID
    api_key = None
    for key in user.get('api_keys', []):
        if key.get('app_id') == app_id:
            api_key = key
            break
    
    if not api_key:
        return jsonify({"error": f"No API key found for app ID {app_id}"}), 404
    
    # Calculate pagination
    skip = (page - 1) * limit
    
    return jsonify({
        "message": "API key retrieved successfully",
        "app_id": app_id,
        "username": username,
        "api_key": api_key.get('key'),
        "created_at": api_key.get('created_at'),
        "pagination": {
            "page": page,
            "limit": limit,
            "total_pages": 1  # For a single API key, there's only 1 page
        }
    }), 200

# Route to retrieve all keys and migrate users
@app.route('/api/retrievekeys', methods=['GET', 'POST'])
def retrieve_keys():
    # Check if app_id is provided in the request
    if request.method == 'POST':
        data = request.get_json()
        app_id = data.get('app_id')
    else:  # GET method
        app_id = request.args.get('app_id')
    
    # Return error if app_id is not provided
    if not app_id:
        return jsonify({
            "error": "Missing app_id parameter",
            "message": "Please provide an app_id to retrieve the associated keys"
        }), 400
    
    # Check if Keys collection exists, if not create it
    if "Keys" not in db.list_collection_names():
        # Create the collection
        db.create_collection("Keys")
    
    # Get all users
    all_users = list(users_collection.find())
    
    # Migrate users to Keys collection if they don't have api_keys field
    for user in all_users:
        # Check if user already has api_keys field
        if 'api_keys' not in user:
            # Initialize empty api_keys field for user
            users_collection.update_one(
                {"_id": user["_id"]},
                {"$set": {"api_keys": []}}
            )
        
        # Check if user exists in Keys collection
        existing_key_user = keys_collection.find_one({"username": user["Username"]})
        if not existing_key_user:
            # Add user to Keys collection
            keys_collection.insert_one({
                "username": user["Username"],
                "keys": user.get("api_keys", [])
            })
    
    # Retrieve all keys from Keys collection that match the app_id
    matching_keys = []
    all_key_users = list(keys_collection.find({}, {"_id": 0}))
    
    for user in all_key_users:
        username = user["username"]
        # Filter keys for this user that match the app_id
        matching_user_keys = [
            key for key in user.get("keys", []) 
            if key.get("app_id") == app_id
        ]
        
        if matching_user_keys:
            matching_keys.append({
                "username": username,
                "keys": matching_user_keys
            })
    
    return jsonify({
        "message": f"Keys retrieved successfully for app_id: {app_id}",
        "keys": matching_keys,
        "total_users": len(matching_keys),
        "total_keys": sum(len(user.get("keys", [])) for user in matching_keys)
    }), 200

# Route to generate a new API key for a user and app
@app.route('/api/newapikey', methods=['POST'])
def new_api_key():
    data = request.get_json()
    
    # Check if required fields are provided
    if not data or 'appId' not in data or 'username' not in data:
        return jsonify({"error": "App ID and username are required"}), 400
    
    app_id = data['appId']
    username = data['username']
    
    # Verify the app exists
    application = applications_collection.find_one({"app_id": app_id})
    if not application:
        return jsonify({"error": f"Application with ID {app_id} not found"}), 404
    
    # Find user in database
    user = users_collection.find_one({"Username": username})
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # Generate a new API key
    new_key = generate_api_key()
    current_time = datetime.datetime.utcnow()
    
    # Prepare the API key object
    api_key_obj = {
        "app_id": app_id,
        "key": new_key,
        "created_at": current_time
    }
    
    # Check if user already has api_keys field
    if 'api_keys' not in user:
        # Initialize api_keys as an empty list
        users_collection.update_one(
            {"Username": username},
            {"$set": {"api_keys": []}}
        )
        
    # Check if there's an existing key for this app
    existing_key_index = None
    for i, key in enumerate(user.get('api_keys', [])):
        if key.get('app_id') == app_id:
            existing_key_index = i
            break
    
    if existing_key_index is not None:
        # Replace the existing key for this app
        update_query = {
            "$set": {f"api_keys.{existing_key_index}": api_key_obj}
        }
    else:
        # Add a new key for this app
        update_query = {
            "$push": {"api_keys": api_key_obj}
        }
    
    # Update the user document
    users_collection.update_one(
        {"Username": username},
        update_query
    )
    
    # Also update Keys collection if it exists
    if "Keys" in db.list_collection_names():
        keys_doc = keys_collection.find_one({"username": username})
        if keys_doc:
            # Check if there's an existing key for this app in the Keys collection
            existing_key_found = False
            for i, key in enumerate(keys_doc.get('keys', [])):
                if key.get('app_id') == app_id:
                    # Update the existing key
                    keys_collection.update_one(
                        {"username": username},
                        {"$set": {f"keys.{i}": api_key_obj}}
                    )
                    existing_key_found = True
                    break
            
            if not existing_key_found:
                # Add a new key
                keys_collection.update_one(
                    {"username": username},
                    {"$push": {"keys": api_key_obj}}
                )
        else:
            # Create a new document for this user
            keys_collection.insert_one({
                "username": username,
                "keys": [api_key_obj]
            })
    
    return jsonify({
        "message": "API key generated successfully",
        "app_id": app_id,
        "username": username,
        "api_key": new_key,
        "created_at": current_time
    }), 201

if __name__ == '__main__':
    app.run(debug=True)