# Cryptographic Key Management System

## Overview
The **Cryptographic Key Management System** is a Python-based utility designed to provide secure key management for encryption and decryption tasks. It supports **AES (Advanced Encryption Standard)** for symmetric encryption, **RSA (Rivest-Shamir-Adleman)** for asymmetric encryption, and **Diffie-Hellman** for secure key exchange. The system also includes a **key revocation** feature to remove keys from the repository when no longer needed.

## Features
- **AES Encryption/Decryption**
  - Uses **256-bit AES in CBC mode** with **PKCS7 padding**
  - Secure key generation using `secrets.token_bytes(32)`
  - Securely encrypts and decrypts data
- **RSA Key Pair Generation**
  - Generates **2048-bit RSA keys**
  - Encrypts and decrypts data using **PKCS1v15 padding**
  - Provides a **public-private key vault** for managing keys
- **Diffie-Hellman Key Exchange**
  - Generates **Diffie-Hellman parameters and key pairs**
  - Enables secure key exchange without direct transmission of keys
- **Key Revocation Mechanism**
  - Supports deletion of AES and RSA keys
  - Prevents unauthorized use of revoked keys

## Prerequisites
To use this system, install Python and the `cryptography` package:
```sh
pip install cryptography
```

## Usage Guide

### 1. Initialize the Key Management System
```python
from key_management import KeyCustodian

kms_instance = KeyCustodian()
```

### 2. Generate and Use an AES Key
#### Step 1: Create an AES Key
```python
aes_key_id = "terminal_123"
secure_aes_key = kms_instance.establish_aes_key(aes_key_id)
print("AES Key Established:", secure_aes_key)
```
#### Step 2: Encrypt Data with AES
```python
aes_encrypted_text = kms_instance.encrypt_data_aes(aes_key_id, "Confidential Communication")
print("AES Encrypted Text:", aes_encrypted_text)
```
#### Step 3: Decrypt Data with AES
```python
aes_decrypted_text = kms_instance.decrypt_data_aes(aes_key_id, aes_encrypted_text)
print("Decrypted AES Text:", aes_decrypted_text)  # Output: Confidential Communication
```

### 3. Generate an RSA Key Pair and Encrypt/Decrypt Data
#### Step 1: Generate RSA Key Pair
```python
rsa_user = "systemRSA"
kms_instance.generate_rsa_pair(rsa_user)
```
#### Step 2: Encrypt Data with RSA
```python
rsa_encrypted_data = kms_instance.encrypt_data_rsa(rsa_user, "Classified Information")
print("RSA Encrypted Data:", rsa_encrypted_data)
```
#### Step 3: Decrypt Data with RSA
```python
rsa_decrypted_data = kms_instance.decrypt_data_rsa(rsa_user, rsa_encrypted_data)
print("Decrypted RSA Text:", rsa_decrypted_data)  # Output: Classified Information
```

### 4. Generate Diffie-Hellman Parameters and Key Pair
```python
dh_private_key, dh_public_key = kms_instance.generate_diffie_hellman_params_and_key()
print("Diffie-Hellman Public Key:", dh_public_key)
```

### 5. Key Revocation
#### Step 1: Revoke an AES or RSA Key
```python
revocation_result = kms_instance.invalidate_key(aes_key_id)
print("Revocation Result:", revocation_result)  # Expected: Key Revocation Successful
```
#### Step 2: Attempt to Decrypt Data After Key Revocation
```python
try:
    kms_instance.decrypt_data_aes(aes_key_id, aes_encrypted_text)
except Exception as e:
    print("Expected error after key revocation:", e)
```

## Security Considerations
- **Strong Key Generation**: Uses `secrets.token_bytes` for secure key generation.
- **Secure Storage**: Keys are stored in memory and not written to disk.
- **Padding Mechanisms**: Uses **PKCS7** for AES and **PKCS1v15** for RSA encryption.
- **Key Revocation**: Prevents unauthorized access by deleting keys from memory.

## Best Practices
- Use **environment variables** or **secure vaults** to store keys securely instead of memory storage.
- Consider **AES-GCM** for authenticated encryption instead of AES-CBC.
- Regularly rotate keys and revoke unused ones to enhance security.
- Log encryption/decryption operations securely without exposing sensitive data.

## License
This project is licensed under the **MIT License**.

## Author
Your Name

