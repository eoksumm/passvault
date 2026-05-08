import os
import base64
import bcrypt
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

def hash_master_password(password: str) -> str:
    # Hash master password using bcrypt.
    pwd_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(pwd_bytes, salt)
    return hashed.decode('utf-8')

def verify_master_password(password: str, hashed_password: str) -> bool:
    # Check if the password is correct 
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

def generate_encryption_salt() -> str:
    # Random salt for encryption
    return base64.b64encode(os.urandom(16)).decode('utf-8')

def _derive_key(master_password: str, salt: str) -> bytes:
    # Create a key from the master password and salt using PBKDF2HMAC.
    salt_bytes = base64.b64decode(salt)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt_bytes,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(master_password.encode('utf-8'))
    return base64.urlsafe_b64encode(key)

def encrypt_vault_data(master_password: str, salt: str, plaintext: str) -> str:
    # Encrypt data.
    key = _derive_key(master_password, salt)
    f = Fernet(key)
    ciphertext = f.encrypt(plaintext.encode('utf-8'))
    return ciphertext.decode('utf-8')

def decrypt_vault_data(master_password: str, salt: str, ciphertext: str) -> str:
    # Decrypt data.
    key = _derive_key(master_password, salt)
    f = Fernet(key)
    plaintext = f.decrypt(ciphertext.encode('utf-8'))
    return plaintext.decode('utf-8')

import secrets
import string

def generate_random_password(length: int = 16) -> str:
    # Make a secure random password
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(alphabet) for _ in range(length))
    return password
