

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.dh import generate_parameters
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64
from cryptography.hazmat.primitives.padding import PKCS7
import secrets

# Cryptographic Key Management System
class KeyCustodian:
    def __init__(self):
        self.symmetric_repository = {}
        self.asymmetric_vault = {}

    def establish_aes_key(self, key_identifier):
        # Generate a 256-bit AES key using secrets for better security
        secure_key = secrets.token_bytes(32)
        self.symmetric_repository[key_identifier] = secure_key
        return base64.b64encode(secure_key).decode()

    def generate_rsa_pair(self, user_designation):
        # Generate an RSA key pair
        private_key_material = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key_material = private_key_material.public_key()
        self.asymmetric_vault[user_designation] = (private_key_material, public_key_material)
        return public_key_material

    def encrypt_data_aes(self, key_identifier, data_to_encrypt):
        # Encrypt plaintext with AES-CBC
        stored_key = self.symmetric_repository[key_identifier]
        initialization_vector = secrets.token_bytes(16)
        cipher_instance = Cipher(algorithms.AES(stored_key), modes.CBC(initialization_vector))
        encryptor_instance = cipher_instance.encryptor()
        padder_instance = PKCS7(algorithms.AES.block_size).padder()
        padded_plaintext = padder_instance.update(data_to_encrypt.encode()) + padder_instance.finalize()
        cipher_text = encryptor_instance.update(padded_plaintext) + encryptor_instance.finalize()
        return base64.b64encode(initialization_vector + cipher_text).decode()

    def decrypt_data_aes(self, key_identifier, encrypted_information):
        # Decrypt AES-CBC encrypted data
        retrieved_key = self.symmetric_repository[key_identifier]
        encrypted_information = base64.b64decode(encrypted_information)
        extracted_iv = encrypted_information[:16]
        extracted_ciphertext = encrypted_information[16:]
        cipher_instance = Cipher(algorithms.AES(retrieved_key), modes.CBC(extracted_iv))
        decryptor_instance = cipher_instance.decryptor()
        decrypted_padded_data = decryptor_instance.update(extracted_ciphertext) + decryptor_instance.finalize()
        unpadder_instance = PKCS7(algorithms.AES.block_size).unpadder()
        unpadded_plaintext = unpadder_instance.update(decrypted_padded_data) + unpadder_instance.finalize()
        return unpadded_plaintext.decode()

    def encrypt_data_rsa(self, user_designation, data_to_hide):
        # Encrypt data using RSA with PKCS1v15 padding
        _, recipient_public_key = self.asymmetric_vault[user_designation]
        encrypted_message = recipient_public_key.encrypt(
            data_to_hide.encode(),
            padding.PKCS1v15()
        )
        return base64.b64encode(encrypted_message).decode()

    def decrypt_data_rsa(self, user_designation, hidden_information):
        # Decrypt RSA encrypted data using PKCS1v15 padding
        user_private_key, _ = self.asymmetric_vault[user_designation]
        decoded_information = base64.b64decode(hidden_information)
        uncovered_message = user_private_key.decrypt(
            decoded_information,
            padding.PKCS1v15()
        )
        return uncovered_message.decode()

    def generate_diffie_hellman_params_and_key(self):
        # Generate Diffie-Hellman parameters and key pair
        dh_parameters = generate_parameters(generator=2, key_size=2048)
        dh_private_key = dh_parameters.generate_private_key()
        dh_public_key = dh_private_key.public_key()
        return dh_private_key, dh_public_key

    def invalidate_key(self, key_identifier):
        # Revoke (delete) a key
        if key_identifier in self.symmetric_repository:
            del self.symmetric_repository[key_identifier]
        elif key_identifier in self.asymmetric_vault:
            del self.asymmetric_vault[key_identifier]
        return "Key Revocation Successful"

# ********************** Test Cases *****************************

# Create an instance of the KMS
kms_instance = KeyCustodian()

# Case 1: Symmetric Key Management (AES)
aes_key_id = "terminal_123"
kms_instance.establish_aes_key(aes_key_id)
aes_encrypted_text = kms_instance.encrypt_data_aes(aes_key_id, "Confidential Communication")
aes_unencrypted_text = kms_instance.decrypt_data_aes(aes_key_id, aes_encrypted_text)
print("Decrypted AES:", aes_unencrypted_text)  #  Output: Confidential Communication

# Case 2: Asymmetric Key Management (RSA)
rsa_user = "systemRSA"
kms_instance.generate_rsa_pair(rsa_user)
rsa_encrypted_data = kms_instance.encrypt_data_rsa(rsa_user, "Classified Information")
rsa_decrypted_data = kms_instance.decrypt_data_rsa(rsa_user, rsa_encrypted_data)
print("Decrypted RSA:", rsa_decrypted_data)  #  Output: Classified Information

# Case 3: Diffie-Hellman Key Exchange (Basic test)
dh_private_key, dh_public_key = kms_instance.generate_diffie_hellman_params_and_key()
print("DH Public Key:", dh_public_key)

# Case 4: Key Revocation Test
revocation_result = kms_instance.invalidate_key(aes_key_id)
print("Revocation Result:", revocation_result)  # Expected: Key Revocation Successful

# Attempt to decrypt AES data after revocation
try:
    kms_instance.decrypt_data_aes(aes_key_id, aes_encrypted_text)
except Exception as e:
    print("Expected error after key revocation:", e)
     
Decrypted AES: Confidential Communication
Decrypted RSA: Classified Information
DH Public Key: <cryptography.hazmat.bindings._rust.openssl.dh.DHPublicKey object at 0x7b7f8f0456b0>
Revocation Result: Key Revocation Successful
Expected error after key revocation: 'terminal_123'