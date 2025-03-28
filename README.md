# Secure Key Management System (KMS)

## Overview
The Secure Key Management System (KMS) provides robust encryption key lifecycle management, including generation, distribution, storage, and revocation. It supports symmetric encryption (AES), asymmetric encryption (RSA), and secure key exchange (Diffie-Hellman/ECDH).

## Features
- **Symmetric Encryption (AES)**: Securely generates and distributes 256-bit AES keys.
- **Asymmetric Encryption (RSA)**: Provides RSA key pair generation for secure communications.
- **Diffie-Hellman Key Exchange**: Establishes shared secret keys securely.
- **Key Revocation Mechanism**: Ensures security by revoking compromised or expired keys.
- **Secure Storage**: Protects encryption keys using cryptographic best practices.
- **Access Control**: Ensures only authenticated users can access keys.

## Installation
Ensure you have Python installed. Install the required dependencies using:

```sh
pip install cryptography
```

## Usage

### 1. Initialize the Key Management System
```python
kms_instance = KeyCustodian()
```

### 2. Generate and Use an AES Key
```python
aes_key_id = "terminal_123"
kms_instance.establish_aes_key(aes_key_id)
encrypted_text = kms_instance.encrypt_data_aes(aes_key_id, "Confidential Data")
decrypted_text = kms_instance.decrypt_data_aes(aes_key_id, encrypted_text)
print("Decrypted AES:", decrypted_text)
```

### 3. Generate and Use an RSA Key Pair
```python
rsa_user = "systemRSA"
kms_instance.generate_rsa_pair(rsa_user)
rsa_encrypted_data = kms_instance.encrypt_data_rsa(rsa_user, "Classified Info")
rsa_decrypted_data = kms_instance.decrypt_data_rsa(rsa_user, rsa_encrypted_data)
print("Decrypted RSA:", rsa_decrypted_data)
```

### 4. Perform Diffie-Hellman Key Exchange
```python
dh_private_key, dh_public_key = kms_instance.generate_diffie_hellman_params_and_key()
print("DH Public Key:", dh_public_key)
```

### 5. Revoke a Key
```python
revocation_result = kms_instance.invalidate_key(aes_key_id)
print("Revocation Result:", revocation_result)
```

## Security Considerations
- **Key Storage**: Ensure keys are stored in a secure environment.
- **Access Control**: Use authentication mechanisms to restrict access.
- **Regular Rotation**: Implement periodic key rotation policies.

## License
This project is open-source and provided for educational purposes.

