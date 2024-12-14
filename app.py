import json
import base64
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for
from encryption import (
    generate_key, 
    encrypt_data, 
    decrypt_data, 
    add_differential_privacy_noise, 
    homomorphic_encrypt, 
    create_tenseal_context,
    homomorphic_encrypt_excel  # Add this new import
)
import os
import jwt
import datetime
import hashlib
import pandas as pd
import io
import uuid
import numpy as np

app = Flask(__name__)

SALT = os.urandom(16)
SECRET_KEY = "nirvah2117"
UPLOAD_FOLDER = 'temp_files'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

data_store = {}
access_logs = []
temp_files = {}

# Create TenSEAL context for homomorphic encryption
context = create_tenseal_context()

def hash_password(password):
    """Create a secure hash of the password"""
    return hashlib.sha256((password + SALT.hex()).encode()).hexdigest()

def log_access(action, status, uuid=None, details=None):
    access_logs.append({
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "action": action,
        "status": status,
        "uuid": uuid,
        "details": details
    })

@app.route("/")
def index():
    return redirect(url_for('encryptor'))

@app.route("/encryptor")
def encryptor():
    return render_template("encryptor.html")

@app.route("/decryptor")
def decryptor():
    return render_template("decryptor.html")

@app.route("/encrypt", methods=["POST"])
def encrypt():
    password = request.form.get("password")
    encryption_method = request.form.get("method", "aes")
    use_noise = request.form.get("use_noise") == 'true'
    data_type = request.form.get("data_type")

    if not password:
        return jsonify({"error": "Password is required"}), 400

    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters long"}), 400

    hashed_password = hash_password(password)
    unique_id = str(os.urandom(16).hex())

    if data_type == 'file':
        if 'file' not in request.files:
            return jsonify({"error": "No file uploaded"}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "No file selected"}), 400

        try:
            df = pd.read_excel(file)
            excel_data = io.BytesIO()
            df.to_excel(excel_data, index=False)
            excel_data.seek(0)
            data = excel_data.getvalue()

            if encryption_method == "homomorphic":
    # Encrypt numeric columns using homomorphic encryption
                encrypted_data = homomorphic_encrypt_excel(df, context)
    
    # Store the encrypted data
                data_store[unique_id] = {
                    "method": "homomorphic",
                    "encrypted_data": encrypted_data,
                    "columns": df.columns.tolist(),
                    "is_file": True
                }
    
    # Save encrypted data to a file
                output_path = os.path.join(UPLOAD_FOLDER, f"{unique_id}_encrypted.tenseal")
                with open(output_path, 'wb') as f:  # Note: opened in binary mode
        # Store the column names and their encrypted data
                    serialized_data = {
                        "columns": df.columns.tolist(),
                        "encrypted_data": {
                            col: base64.b64encode(data).decode('utf-8') if isinstance(data, bytes) else None 
                            for col, data in encrypted_data.items()
                        }
                    }
                    f.write(json.dumps(serialized_data).encode('utf-8'))
    
                return jsonify({
                    "id": unique_id, 
                    "method": "homomorphic", 
                    "is_file": True,
                    "file_path": output_path
                })
            
            else:  # AES encryption
                key = generate_key()
                if use_noise:
                    noise_columns = json.loads(request.form.get('noise_columns', '[]'))
        
        # Apply noise only to specified columns
                    for col in noise_columns:
                        if col in df.columns and pd.api.types.is_numeric_dtype(df[col]):
                            df[col] = df[col] + np.random.laplace(0, 1, len(df))
        
                    noisy_excel = io.BytesIO()
                    df.to_excel(noisy_excel, index=False)
                    noisy_excel.seek(0)
                    noisy_data = noisy_excel.getvalue()
        
        # Store original file
                    original_path = os.path.join(UPLOAD_FOLDER, f"{unique_id}_original.xlsx")
                    file.seek(0)
                    df_original = pd.read_excel(file)
                    df_original.to_excel(original_path, index=False)
                else:
                    noisy_data = data

                iv, encrypted_data = encrypt_data(key, noisy_data)
                data_store[unique_id] = {
                    "key": key,
                    "iv": iv,
                    "encrypted_data": encrypted_data,
                    "method": "aes",
                    "is_file": True,
                    "use_noise": use_noise,
                    "password_hash": hashed_password,
                    "original_file": original_path if use_noise else None
                }
                
                return jsonify({
                    "id": unique_id,
                    "encrypted_data": "File encrypted successfully",
                    "is_file": True,
                    "method": "aes"
                })

        except Exception as e:
            return jsonify({"error": f"Error processing Excel file: {str(e)}"}), 400

    else:  # Text data
        data = request.form.get("data")
        if not data:
            return jsonify({"error": "Data is required"}), 400

        # Original text encryption logic
        original_data = data
        if use_noise:
            data = add_differential_privacy_noise(data)

        if encryption_method == "homomorphic":
            encrypted_data = homomorphic_encrypt(data, context)
            data_store[unique_id] = {
                "encrypted_data": encrypted_data,
                "method": "homomorphic"
            }
            return jsonify({"id": unique_id, "method": "homomorphic"})
        else:
            key = generate_key()
            iv, encrypted_data = encrypt_data(key, data)
            data_store[unique_id] = {
                "key": key,
                "iv": iv,
                "encrypted_data": encrypted_data,
                "method": "aes",
                "use_noise": use_noise,
                "password_hash": hashed_password,
                "original_data": original_data
            }
            return jsonify({
                "id": unique_id,
                "encrypted_data": encrypted_data,
                "iv": iv,
                "method": "aes"
            })

@app.route("/generate-token", methods=["POST"])
def generate_token():
    unique_id = request.json.get("id")
    if not unique_id or unique_id not in data_store:
        log_access("generate_token", "failure", unique_id, "Invalid or missing ID")
        return jsonify({"error": "Invalid or missing ID"}), 400

    expiration_time = datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
    token = jwt.encode({"id": unique_id, "exp": expiration_time}, SECRET_KEY, algorithm="HS256")
    log_access("generate_token", "success", unique_id, "Token generated successfully")

    return jsonify({"token": token})

@app.route("/decrypt", methods=["POST"])
def decrypt():
    token = request.json.get("token")
    password = request.json.get("password")

    if not token or not password:
        log_access("decrypt", "failure", details="Missing token or password")
        return jsonify({"error": "Token and password are required"}), 400

    if len(password) < 6:
        log_access("decrypt", "failure", details="Password too short")
        return jsonify({"error": "Password must be at least 6 characters long"}), 400

    try:
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        unique_id = decoded_token.get("id")
        encrypted_data = data_store.get(unique_id)
        
        if not encrypted_data:
            log_access("decrypt", "failure", unique_id, "Data not found")
            return jsonify({"error": "Data not found"}), 404

        if encrypted_data.get("method") == "homomorphic":
            if encrypted_data.get("is_file", False):
                return jsonify({
                    "error": "Homomorphically encrypted files cannot be decrypted",
                    "is_file": True
                }), 400
            return jsonify({"error": "Homomorphic decryption not supported"}), 400

        # Verify password
        hashed_input_password = hash_password(password)
        if hashed_input_password != encrypted_data.get("password_hash"):
            log_access("decrypt", "failure", unique_id, "Incorrect password")
            return jsonify({"error": "Incorrect password"}), 401

        # Handle file decryption
        if encrypted_data.get("is_file", False):
            decrypted_data = decrypt_data(
                encrypted_data["key"],
                encrypted_data["iv"],
                encrypted_data["encrypted_data"]
            )
            
            # Generate temporary file for download
            temp_file_id = str(uuid.uuid4())
            temp_file_path = os.path.join(UPLOAD_FOLDER, f"{temp_file_id}.xlsx")
            
            with open(temp_file_path, 'wb') as f:
                f.write(decrypted_data)
            
            temp_files[temp_file_id] = {
                "path": temp_file_path,
                "timestamp": datetime.datetime.utcnow()
            }

            response_data = {
                "is_file": True,
                "file_id": temp_file_id
            }

            if encrypted_data.get("use_noise"):
                response_data["noise_applied"] = True
                response_data["original_file_id"] = unique_id

            log_access("decrypt", "success", unique_id, "File decryption successful")
            return jsonify(response_data)

        else:  # Handle text decryption
            decrypted_data = decrypt_data(
                encrypted_data["key"],
                encrypted_data["iv"],
                encrypted_data["encrypted_data"]
            ).decode('utf-8')
            
            response_data = {"data": decrypted_data}
            
            if encrypted_data.get("use_noise"):
                response_data["noise_applied"] = True
                response_data["original_data"] = encrypted_data.get("original_data")

            log_access("decrypt", "success", unique_id, "Text decryption successful")
            return jsonify(response_data)

    except jwt.ExpiredSignatureError:
        log_access("decrypt", "failure", details="Token expired")
        return jsonify({"error": "Token has expired"}), 401

    except jwt.InvalidTokenError:
        log_access("decrypt", "failure", details="Invalid token")
        return jsonify({"error": "Invalid token"}), 401

@app.route('/download/<file_id>', methods=['GET'])
def download_file(file_id):
    temp_file_info = temp_files.get(file_id)
    
    if not temp_file_info:
        log_access("download", "failure", file_id, "File not found")
        return jsonify({"error": "File not found"}), 404

    temp_file_path = temp_file_info["path"]
    
    if not os.path.exists(temp_file_path):
        log_access("download", "failure", file_id, "File no longer exists")
        return jsonify({"error": "File no longer exists"}), 404

    log_access("download", "success", file_id, "File downloaded successfully")
    return send_file(temp_file_path, as_attachment=True, download_name=f"{file_id}.xlsx")


@app.route('/download_encrypted/<file_id>', methods=['GET'])
def download_encrypted_file(file_id):
    encrypted_data = data_store.get(file_id)
    
    if not encrypted_data or encrypted_data.get("method") != "homomorphic":
        log_access("download_encrypted", "failure", file_id, "Invalid file or not homomorphically encrypted")
        return jsonify({"error": "File not found or not homomorphically encrypted"}), 404

    output_path = os.path.join(UPLOAD_FOLDER, f"{file_id}_encrypted.tenseal")
    
    if not os.path.exists(output_path):
        log_access("download_encrypted", "failure", file_id, "Encrypted file not found")
        return jsonify({"error": "Encrypted file not found"}), 404

    log_access("download_encrypted", "success", file_id, "Encrypted file downloaded successfully")
    return send_file(
        output_path,
        as_attachment=True,
        download_name=f"encrypted_data_{file_id}.tenseal",
        mimetype='application/octet-stream'
    )    

if __name__ == "__main__":
    app.run(debug=True)
