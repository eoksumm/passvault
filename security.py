import os
import base64
import secrets
import string
import bcrypt
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet


def hash_master_password(password: str) -> str:
    pwd_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(pwd_bytes, salt)
    return hashed.decode('utf-8')


def verify_master_password(password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))


def generate_encryption_salt() -> str:
    return base64.b64encode(os.urandom(16)).decode('utf-8')


def _derive_key(master_password: str, salt: str) -> bytes:
    salt_bytes = base64.b64decode(salt)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt_bytes,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode('utf-8')))


def encrypt_vault_data(master_password: str, salt: str, plaintext: str) -> str:
    key = _derive_key(master_password, salt)
    return Fernet(key).encrypt(plaintext.encode('utf-8')).decode('utf-8')


def decrypt_vault_data(master_password: str, salt: str, ciphertext: str) -> str:
    key = _derive_key(master_password, salt)
    return Fernet(key).decrypt(ciphertext.encode('utf-8')).decode('utf-8')


def generate_random_password(length: int = 16) -> str:
    # Exclude chars that cause display/copy issues in HTML contexts
    alphabet = string.ascii_letters + string.digits + '!@#$%^&*()-_=+[]{}|;:,.<>?'
    return ''.join(secrets.choice(alphabet) for _ in range(length))
