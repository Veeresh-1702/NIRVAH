import pandas as pd
import tenseal as ts
import numpy as np
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

def generate_key():
    return get_random_bytes(32)

def create_tenseal_context():
    context = ts.context(
        ts.SCHEME_TYPE.CKKS,
        poly_modulus_degree=8192,
        coeff_mod_bit_sizes=[60, 40, 60]
    )
    context.global_scale = 2**40
    context.generate_galois_keys()
    context.generate_relin_keys()
    return context

def encrypt_data(key, data):
    """
    Encrypt data using AES. Can handle both string and binary data.
    """
    cipher = AES.new(key, AES.MODE_CBC)
    
    if isinstance(data, str):
        data = data.encode('utf-8')  # Ensure text is in byte format
    
    elif isinstance(data, bytes):
        # Data is already in byte format (Excel file)
        pass
    else:
        raise ValueError("Unsupported data type")

    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv, ct

def homomorphic_encrypt_excel(df, context):
    """Encrypt Excel data using homomorphic encryption (TenSEAL)."""
    encrypted_data = {}
    
    # Encrypt each numeric column
    for column in df.columns:
        if pd.api.types.is_numeric_dtype(df[column]):
            float_data = df[column].astype(float).tolist()
            encrypted_vector = ts.ckks_vector(context, float_data)
            # Serialize the encrypted vector
            encrypted_data[column] = encrypted_vector.serialize()
    
    return encrypted_data

def decrypt_data(key, iv, ciphertext):
    """
    
    """
    iv = base64.b64decode(iv)
    ciphertext = base64.b64decode(ciphertext)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_data  # This will return bytes for files and string for text data


def add_differential_privacy_noise(data):
    """Add Laplace noise to string data"""
    if isinstance(data, str):
        noise = np.random.laplace(0, 1, len(data))
        noisy_data = ''.join(chr(max(0, min(255, ord(char) + int(noise_val)))) 
                            for char, noise_val in zip(data, noise))
        return noisy_data
    return data

def homomorphic_encrypt(data, context):
    """Encrypt data using homomorphic encryption (TenSEAL)."""
    if isinstance(data, str):
        float_data = [float(ord(char)) for char in data]
    else:
        float_data = [float(x) for x in data]
    encrypted_vector = ts.ckks_vector(context, float_data)
    return encrypted_vector

def homomorphic_decrypt(encrypted_vector):
    """Decrypt data using homomorphic encryption (TenSEAL)."""
    decrypted_data = encrypted_vector.decrypt()
    return ''.join([chr(int(value)) for value in decrypted_data])