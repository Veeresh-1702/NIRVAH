import tenseal as ts

# Create the encryption context
context = ts.context(ts.SCHEME_TYPE.CKKS, poly_modulus_degree=8192, coeff_mod_bit_sizes=[60, 40, 60])

# Generate keys for encryption
context.generate_galois_keys()
context.make_context_public()

# Create an encryptor object
encryptor = context.encryptor()

# Example data to encrypt (a list of floats or tensor)
data = [1.0, 2.0, 3.0]  # Simple numeric data

# Encrypt the data using encrypt_tensor method
encrypted_data = encryptor.encrypt_tensor(data)
print("Encrypted Data:", encrypted_data)

# Decrypt the data (to verify encryption works)
decryptor = context.decryptor()
decrypted_data = decryptor.decrypt(encrypted_data)
print("Decrypted Data:", decrypted_data)
