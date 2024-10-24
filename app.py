import json
import uuid
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt
# from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename, send_from_directory
import os
# from datetime import timedelta

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'mysecretkey'
# app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)  # Set expiration time for the token
jwt = JWTManager(app)
CORS(app)
CORS(app, resources={r"/*": {"origins": "*"}})  
json_file_path = 'data.json'
# app.config['UPLOAD_FOLDER'] = '/tmp/'
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')

# Ensure the 'uploads' folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])
def load_data():
    if not os.path.exists(json_file_path):
        return {'users': []}  # Return an empty structure if the file doesn't exist
    with open(json_file_path, 'r') as f:
        return json.load(f)

def save_data(data):
    with open('data.json', 'w') as f:
        json.dump(data, f, indent=4)
        
        
def create_admin_user():
    data = load_data()
    users = data['users']
    admin_user = next((user for user in users if user['username'] == 'admin'), None)
    if admin_user is None:
        # hashed_password = generate_password_hash('a', method='sha256')
        admin_user = {
            'user_id': '01',
            'username': 'admin',
            'password': 'a',
            'role': 'admin',
            'email': "sricharangone12@gmail.com",
            'contactNo': "+91 9381795726",
            'address': "MRCET Hostel",
            "organization": "MRCET"
        }
        
        users.append(admin_user)
        
        save_data(data)
        
        print("Admin user created successfully!")
    else:
        print("Admin user already exists.")

create_admin_user()


@app.route('/login', methods=['POST'])
def login():
    create_admin_user()
    username = request.json.get('username')
    password = request.json.get('password')

    data = load_data()
    users = data['users']
    user = next((user for user in users if user['username'] == username), None)    
    if user and (user['password'] == password):
        access_token = create_access_token(identity=user['username'], additional_claims={'role': user['role']})
        print("User logged in at line 68")
        return jsonify({'success': True, 'access_token': access_token, 'role': user['role'], 'userid': (user['username'])}), 200
    else:
        return jsonify({'success': False, 'message': 'Invalid credentials.'}), 400


#######################################################################
# Create a new user

@app.route('/users', methods=['POST'])
@jwt_required()
def register():
    jwt_payload = get_jwt()
    if 'role' in jwt_payload and jwt_payload['role'] in ['admin']:
        username = request.json.get('username')
        password = request.json.get('password') 
        role = request.json.get('role')
        email = request.json.get('email')
        contactNo = request.json.get('contactNo')
        address = request.json.get('address')
        organization = request.json.get('organization')

        if (role == 'admin' or role == 'tender_manager') and not email.endswith('@gmail.com'):
            return jsonify({'success': False, 'message': 'Invalid email domain for admin or tender_manager role.'}), 400
        user_id = str(uuid.uuid4())
        data = load_data() 
        users = data['users']
        existing_user = next((user for user in users if user['username'] == username), None)

        if existing_user is None:
            # hashed_password = generate_password_hash(password, method='sha256')
            new_user = {
                'user_id': user_id,
                'username': username,
                'password': password,
                'role': role,
                'email': email,
                'contactNo': contactNo,
                'address': address,
                'organization': organization,
            }                                                          
            users.append(new_user)
            save_data(data)
            return jsonify({'success': True}), 200
        else:
            return jsonify({'success': False, 'message': 'User already exists.'}), 422
    else:
        return jsonify({'success': False, 'message': 'Not authorized to create users.'}), 401
    
    
@app.route('/users', methods=['GET'])
@jwt_required()
def get_users():
    jwt_payload = get_jwt()
    
    # Check if the user has the required role
    if 'role' in jwt_payload and jwt_payload['role'] in ['admin', 'tender_manager']:
        role = request.args.get('role')
        
        # Load user data from the JSON file
        data = load_data()
        users = data['users']
        
        # Filter users based on the role query parameter
        if role == 'vendor':
            filtered_users = [user for user in users if user['role'] == 'vendor']
        else:
            filtered_users = users
        
        # Remove password from the user data before returning
        for user in filtered_users:
            user.pop('password', None)  # Remove password field if it exists

        return jsonify({'success': True, 'users': filtered_users}), 200
    else:
        return jsonify({'success': False, 'message': 'Not authorized to access users.'}), 401



@app.route('/users/<user_id>', methods=['GET'])
@jwt_required()
def get_user(user_id):
    jwt_payload = get_jwt()
    
    # Check if the user has the required role
    if 'role' in jwt_payload and jwt_payload['role'] == 'admin':
        data = load_data()
        users = data['users']
        
        # Find user by user_id
        user = next((user for user in users if user['username'] == user_id), None)
        
        if user is not None:
            user['user_id'] = str(user_id)  # Mocking the ObjectId
            user.pop('password', None)  # Remove password from response
            return jsonify({'success': True, 'user': user}), 200
        else:
            return jsonify({'success': False, 'message': 'User not found.'}), 404
    else:
        return jsonify({'success': False, 'message': 'Not authorized to access user.'}), 401

# Update an existing user
@app.route('/users/<user_id>', methods=['PUT'])
@jwt_required()
def update_user(user_id):
    jwt_payload = get_jwt()
    
    # Check if the user has the required role
    if 'role' in jwt_payload and jwt_payload['role'] == 'admin':
        data = load_data()
        users = data['users']
        
        # Find user by user_id
        user = next((user for user in users if user['username'] == user_id), None)
        
        if user:
            # Update user details
            username = request.json.get('username')
            password = request.json.get('password')
            role = request.json.get('role')
            email = request.json.get('email')
            contactNo = request.json.get('contactNo')
            address = request.json.get('address')
            organization = request.json.get('organization')

            if username:
                user['username'] = username
            if password:                           
                # hashed_password = generate_password_hash(password, method='sha256')
                user['password'] = password
            if role:
                user['role'] = role
            if email:
                user['email'] = email
            if contactNo:
                user['contactNo'] = contactNo
            if address:
                user['address'] = address
            if organization:
                user['organization'] = organization
            
            # Save updated user list back to JSON file
            save_data(data)

            user['user_id'] = str(user_id)  # Mocking the ObjectId
            user.pop('password', None)  # Remove password from response

            return jsonify({'success': True, 'user': user}), 200
        else:
            return jsonify({'success': False, 'message': 'User not found.'}), 404
    else:
        return jsonify({'success': False, 'message': 'Not authorized to update user details.'}), 401

@app.route('/users/<userid>', methods=['DELETE'])
@jwt_required()
def delete_user(userid):
    jwt_payload = get_jwt()
    
    if 'role' in jwt_payload and jwt_payload['role'] == 'admin':
        data = load_data()
        users = data['users']
        
        # Check if the user is the admin user
        user = next((user for user in users if user['username'] == userid), None)
        if user and user['username'] == 'admin':
            return jsonify({'success': False, 'message': 'The admin user cannot be deleted.'}), 400
        
        if user:
            users.remove(user)  # Remove the user from the list
            save_data(data)      # Save the updated list back to the JSON file
            return jsonify({'success': True}), 200
        else:
            return jsonify({'success': False, 'message': 'User not found.'}), 404
    else:
        return jsonify({'success': False, 'message': 'Not authorized to delete user.'}), 401

# Create a new tender
@app.route('/tenders', methods=['POST'])
@jwt_required()
def create_tender():
    jwt_payload = get_jwt()
    if 'role' in jwt_payload and jwt_payload['role'] == 'tender_manager':
        title = request.json.get('title')
        description = request.json.get('description')
        start_date = request.json.get('start_date')
        deadline = request.json.get('deadline')
        location = request.json.get('location')
        owner = request.args.get('userid')
        
        tender_id = str(uuid.uuid4())
        data = load_data()
        tenders = data['tenders']
        existing_tender = next((tender for tender in data['tenders'] if tender['title'] == title), None)
        
        if existing_tender is None:
            new_tender = {
                'tender_id': tender_id,
                'title': title,
                'description': description,
                'start_date': start_date,
                'deadline': deadline,
                'location': location,
                'status': 'Open',
                'owner': owner
            }
            tenders.append(new_tender)
            save_data(data)  # Save updated tenders list    
            return jsonify({'success': True}), 200
        else:
            return jsonify({'success': False, 'message': 'Tender already exists.'}), 422
    else:
        return jsonify({'success': False, 'message': 'Not authorized to create tender.'}), 401

# Get all tenders
@app.route('/tenders', methods=['GET'])
@jwt_required()
def get_all_tenders():
    jwt_payload = get_jwt()
    if 'role' in jwt_payload and jwt_payload['role'] in ['admin', 'tender_manager']:
        owner_id = request.args.get('userid')
        data = load_data()
        # Filter tenders by owner
        tenders = [tender for tender in data['tenders'] if tender['owner'] == owner_id]
        for tender in tenders:
            tender['_id'] = str(tender['title'])  # Using title as ID for simplicity
        return jsonify({'success': True, 'tenders': tenders}), 200
    else:
        return jsonify({'success': False, 'message': 'Not authorized to access tenders.'}), 401

# Get a specific tender
@app.route('/tenders/<tender_id>', methods=['GET'])
@jwt_required()
def get_tender(tender_id):
    jwt_payload = get_jwt()
    
    if 'role' in jwt_payload and jwt_payload['role'] in ['admin', 'tender_manager']:
        data = load_data()
        
        # Find tender by title
        tender = next((tender for tender in data['tenders'] if tender['title'] == tender_id), None)
        
        if tender is not None:
            tender['_id'] = str(tender['title'])  # Using title as ID for simplicity
            return jsonify({'success': True, 'tender': tender}), 200
        else:
            return jsonify({'success': False, 'message': 'Tender not found.'}), 404
    else:
        return jsonify({'success': False, 'message': 'Not authorized to access tender.'}), 401
    
    
    
@app.route('/tenders/<tender_id>', methods=['DELETE'])
@jwt_required()
def delete_tender(tender_id):
    jwt_payload = get_jwt()
    
    if 'role' in jwt_payload and jwt_payload['role'] in ['admin', 'tender_manager']:
        data = load_data()
        tenders = data['tenders']
        
        # Find the tender by title since we are using a JSON file
        tender = next((tender for tender in tenders if tender['title'] == tender_id), None)
        if not tender:
            return jsonify({'success': False, 'message': 'Tender not found.'}), 404

        # Check for assigned vendors
        assigned_vendors = tender.get('assigned_vendors', [])
        if assigned_vendors:
            return jsonify({'success': False, 'message': 'Cannot delete tender as it is assigned to one or more vendors.'}), 400

        # Remove the tender from the list
        tenders.remove(tender)
        save_data(data)  # Save the updated tenders list back to the JSON file
        
        return jsonify({'success': True}), 200
    else:
        return jsonify({'success': False, 'message': 'Not authorized to delete tender.'}), 401

# Assign a tender to a list of vendors
@app.route('/tenders/assign', methods=['POST'])
@jwt_required()
def assign_tender():
    jwt_payload = get_jwt()
    if 'role' in jwt_payload and jwt_payload['role'] == 'tender_manager':
        tender_id = request.json.get('tender_id')
        vendor_ids = request.json.get('vendor_ids')
        print(tender_id)
        print(vendor_ids)
        if not tender_id or not vendor_ids:
            return jsonify({'status': 'fail', 'message': 'Missing required fields'}), 400
        
        data = load_data()
        # print(data['tenders'])
        # print(tender for tender in data['tenders'] if tender['title'] == tender_id)
        tender = next((tender for tender in data['tenders'] if tender['title'] == tender_id), None)
        if not tender:
            print("failed at 367")
            return jsonify({'status': 'fail', 'message': 'Tender not found'}), 404

        # Get the current vendor data
        vendors = [vendor for vendor in data['users'] if vendor['username'] in vendor_ids]

        if not vendors:
            print("failed at 374")
            return jsonify({'status': 'fail', 'message': 'No vendors found with provided IDs'}), 404

        # Update each vendor's assigned_tenders list
        for vendor in vendors:
            if 'assigned_tenders' not in vendor:
                vendor['assigned_tenders'] = []
            if tender_id not in vendor['assigned_tenders']:
                vendor['assigned_tenders'].append(tender_id)

            # Save the updated vendor list back to the JSON data
            save_data(data)

        # Update the tender's assigned_vendors list
        if 'assigned_vendors' not in tender:
            tender['assigned_vendors'] = []
        for vendor_id in vendor_ids:
            if vendor_id not in tender['assigned_vendors']:
                tender['assigned_vendors'].append(vendor_id)

        # Save the updated tender list back to the JSON data
        save_data(data)

        return jsonify({'status': 'success', 'message': 'Tender assigned to vendors successfully'}), 200
    else:
        return jsonify({'status': 'fail', 'message': 'Unauthorized access'}), 401
    
    
# Get all tenders assigned to a vendor
@app.route('/tenders/vendors/<vendor_id>', methods=['GET'])
@jwt_required()
def get_tenders_by_vendor(vendor_id):
    jwt_payload = get_jwt()
    if 'role' in jwt_payload and jwt_payload['role'] == 'vendor':
        data = load_data()
        print("dataloaded")
        tenders = [tender for tender in data['tenders'] if vendor_id in tender.get('assigned_vendors', [])]
          
        return jsonify({'status': 'success', 'tenders': tenders}), 200
    else:
        return jsonify({'status': 'fail', 'message': 'Unauthorized access'}), 401

# Update an existing tender
@app.route('/tenders/<tender_id>', methods=['PUT'])
@jwt_required()
def update_tender(tender_id):
    jwt_payload = get_jwt()
    
    if 'role' in jwt_payload and jwt_payload['role'] == 'tender_manager':
        data = load_data()
        tender = next((tender for tender in data['tenders'] if tender['title'] == tender_id), None)
        
        if tender:
            # Update tender details
            title = request.json.get('title')
            description = request.json.get('description')
            start_date = request.json.get('start_date')
            deadline = request.json.get('deadline')
            location = request.json.get('location')
            status = request.json.get('status')

            if title:
                tender['title'] = title
            if description:
                tender['description'] = description
            if start_date:
                tender['start_date'] = start_date
            if deadline:
                tender['deadline'] = deadline
            if location:
                tender['location'] = location
            if status:
                tender['status'] = status

            save_data(data)  # Save updated tender list back to JSON
            tender['_id'] = str(tender['_id'])  # Convert ObjectId to string
            
            return jsonify({'success': True, 'message': 'Tender updated successfully', 'tender': tender}), 200
        else:
            return jsonify({'success': False, 'message': 'Tender not found.'}), 404
    else:
        return jsonify({'success': False, 'message': 'Not authorized to access tender.'}), 401

# Create a new quotation
@app.route('/quotations', methods=['POST'])
@jwt_required()
def create_quotation():
    print('create_quotation')
    jwt_payload = get_jwt()
    quotation_id = str(uuid.uuid4())
    if 'role' in jwt_payload and jwt_payload['role'] == 'vendor':
        # Use the correct parameter name
        tender_id = request.args.get('tender_id')
        print(tender_id)
        
        vendor_id = request.args.get('userid')
        print(vendor_id)
        
        vendor_name = jwt_payload['sub']
        amount = request.form.get('amount')
        currency = request.form.get('currency')
        validity_days = request.form.get('validity_days')
        description = request.form.get('description')
        file = request.files.get('file')
        
        if not tender_id or not amount or not currency or not validity_days:
            return jsonify({'success': False, 'message': 'Missing required fields'}), 400
        
        data = load_data()
            
        existing_quotation = next((q for q in data['quotations'] if q['tender_id'] == tender_id and q['vendor_id'] == vendor_id), None)
        
        if existing_quotation:
            return jsonify({'success': False, 'message': 'Vendor has already submitted a quotation for this tender'}), 400

        tender = next((tender for tender in data['tenders'] if tender['title'] == tender_id), None)
        if not tender:
            return jsonify({'success': False, 'message': 'Tender not found'}), 404
        
        quotation = {
            'tender_id': tender_id,
            'vendor_id': vendor_id,
            'vendor_name': vendor_name,
            'amount': amount,
            'currency': currency,
            'validity_days': validity_days,
            'description': description,
            'status': 'submitted'
        }

        if file:
            quotation['file_name'] = file.filename
            
        data['quotations'].append(quotation)
        save_data(data)  # Save updated quotations list back to JSON
        
        if file:
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        
        quotation['_id'] = str(len(data['quotations']))  # Mock ID for the quotation
        
        return jsonify({'success': True, 'message': 'Quotation created successfully', 'quotation': quotation}), 200
    else:
        return jsonify({'success': False, 'message': 'Unauthorized access'}), 401

    
@app.route('/tenders/<tender_id>/quotations', methods=['GET'])
@jwt_required()
def get_quotations_for_tender(tender_id):
    jwt_payload = get_jwt()
    if 'role' in jwt_payload and jwt_payload['role'] == 'tender_manager':
        data = load_data()
        tender = next((tender for tender in data['tenders'] if tender['title'] == tender_id), None)
        
        if tender:
            quotations = [q for q in data['quotations'] if q['tender_id'] == tender_id]
            for quotation in quotations:
                quotation['_id'] = str(quotations.index(quotation) + 1)  # Mock ID
            return jsonify({'success': True, 'quotations': quotations}), 200
        else:
            return jsonify({'success': False, 'message': 'Tender not found.'}), 404
    else:
        return jsonify({'success': False, 'message': 'Not authorized to access tender.'}), 401

# GET the quotation created by a vendor for a given tender
@app.route('/tenders/<tender_id>/quotations/<vendor_id>', methods=['GET'])
@jwt_required()
def get_quotation_for_tender_and_vendor(tender_id, vendor_id):
    jwt_payload = get_jwt()
    if 'role' in jwt_payload and jwt_payload['role'] == 'vendor':
        data = load_data()
        tender = next((tender for tender in data['tenders'] if tender['title'] == tender_id), None)
        
        if tender:
            quotation = next((q for q in data['quotations'] if q['tender_id'] == tender_id and q['vendor_id'] == vendor_id), None)
            if quotation:
                quotation['_id'] = str(data['quotations'].index(quotation) + 1)  # Mock ID
                return jsonify({'success': True, 'quotation': quotation}), 200
            else:
                return jsonify({'success': False, 'message': 'Quotation not found for the given tender and vendor.'}), 404
        else:
            return jsonify({'success': False, 'message': 'Tender not found.'}), 404
    else:
        return jsonify({'success': False, 'message': 'Not authorized to access tender.'}), 401

# Update an existing quotation
@app.route('/quotations/<quotation_id>', methods=['PUT'])
@jwt_required()
def update_quotation(quotation_id):
    jwt_payload = get_jwt()
    vendor_id = request.args.get('userid')
    
    if 'role' in jwt_payload and jwt_payload['role'] == 'vendor':
        data = load_data()
        quotation = next((q for q in data['quotations'] if str(q['_id']) == quotation_id), None)
        
        if quotation:
            # Update quotation details
            amount = request.form.get('amount')
            currency = request.form.get('currency')
            validity_days = request.form.get('validity_days')
            description = request.form.get('description')
            file = request.files.get('file')
            
            if amount:
                quotation['amount'] = amount
            if currency:
                quotation['currency'] = currency
            if validity_days:
                quotation['validity_days'] = validity_days
            if description:
                quotation['description'] = description
            if file:
                quotation['file_name'] = file.filename

            save_data(data)  # Save updated quotations back to JSON
            
            if file:
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            
            return jsonify({'success': True, 'message': 'Quotation updated successfully', 'quotation': quotation}), 200
        else:
            return jsonify({'success': False, 'message': 'Quotation not found'}), 404
    else:
        return jsonify({'success': False, 'message': 'Unauthorized access'}), 401

# Update decision (accepted/rejected) for a quotation
@app.route('/quotations/<quotation_id>/decision', methods=['PUT'])
@jwt_required()
def decide_quotation(quotation_id):
    jwt_payload = get_jwt()
    
    if 'role' in jwt_payload and jwt_payload['role'] == 'tender_manager':
        data = load_data()  
        quotation = next((q for q in data['quotations'] if str(q['_id']) == quotation_id), None)
        
        if quotation:
            decision = request.json.get('status')
            tender_id = quotation['tender_id']
            if decision and decision in ['accepted', 'rejected']:
                if decision == 'accepted':
                    # Update current quotation to accepted
                    quotation['status'] = 'accepted'
                    # Update all other quotations to rejected
                    for q in data['quotations']:
                        if q['tender_id'] == tender_id and q['_id'] != quotation_id:
                            q['status'] = 'rejected'
                else:
                    quotation['status'] = 'rejected'
                
                save_data(data)  # Save updated quotations back to JSON
                return jsonify({'success': True, 'message': 'Quotation decision updated successfully.'}), 200
            else:
                return jsonify({'success': False, 'message': 'Invalid decision.'}), 400
        else:
            return jsonify({'success': False, 'message': 'Quotation not found.'}), 404
    else:
        return jsonify({'success': False, 'message': 'Unauthorized access.'}), 401

# Delete a quotation
@app.route('/tenders/<tender_id>/quotations/<vendor_id>', methods=['DELETE'])
@jwt_required()
def delete_quotation(tender_id, vendor_id):
    jwt_payload = get_jwt()
    
    if 'role' in jwt_payload and jwt_payload['role'] == 'vendor':
        data = load_data()
        quotation = next((q for q in data['quotations'] if q['tender_id'] == tender_id and q['vendor_id'] == vendor_id), None)
        
        if quotation:
            data['quotations'].remove(quotation)
            save_data(data)  # Save updated quotations back to JSON
            return jsonify({'success': True, 'message': 'Quotation deleted successfully'}), 200
        else:
            return jsonify({'success': False, 'message': 'Quotation not found'}), 404
    else:
        return jsonify({'success': False, 'message': 'You are not authorized to delete this quotation'}), 401

@app.route('/upload', methods=['POST'])
@jwt_required()
def upload_file():
    jwt_payload = get_jwt()
    
    if 'role' in jwt_payload and jwt_payload['role'] == 'vendor':
        if 'file' not in request.files:
            return jsonify({'success': False, 'message': 'No file part in the request.'}), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({'success': False, 'message': 'No selected file.'}), 400
        
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return jsonify({'success': True, 'message': 'File uploaded successfully!'}), 200
    else:
        return jsonify({'success': False, 'message': 'Unauthorized to upload files.'}), 401

# Retrieve a file
@app.route('/uploads/<filename>', methods=['GET'])
def download_file(filename):
    try:
        print(f"UPLOAD_FOLDER: {app.config['UPLOAD_FOLDER']}")
        print(f"Requested filename: {filename}")
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True, environ=request.environ)
    except FileNotFoundError:
        print(f"File not found: {filename}")
        return jsonify({'success': False, 'message': 'File not found.'}), 404

# @app.route('/uploads/<filename>', methods=['GET'])
# def download_file(filename):
#     try:
#         # C:\Users\asamp\Desktop\TQMS2\server\uploads\Screenshot_2024-10-15_145203.png
#         full_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
#         print(f"Looking for file: {full_path}")  # Debugging line
#         return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True, environ=request.environ)
#     except FileNotFoundError:
#         return jsonify({'success': False, 'message': 'File not found.'}), 404


# Close a tender
@app.route('/tenders/close/<tender_id>', methods=['PUT'])
@jwt_required()
def close_tender(tender_id):
    jwt_payload = get_jwt()
    
    if 'role' in jwt_payload and jwt_payload['role'] == 'tender_manager':
        data = load_data()
        tender = next((tender for tender in data['tenders'] if tender['title'] == tender_id), None)
        
        if tender is None:
            return jsonify({'success': False, 'message': 'Tender not found.'}), 404
        
        if tender['status'] != 'Open':
            return jsonify({'success': False, 'message': 'Tender already closed.'}), 422
        
        # Update tender status to Closed
        tender['status'] = 'Closed'
        save_data(data)  # Save updated data to JSON
        
        return jsonify({'success': True, 'message': 'Tender closed successfully.'}), 200
    else:
        return jsonify({'success': False, 'message': 'Not authorized to close tender.'}), 401
    
