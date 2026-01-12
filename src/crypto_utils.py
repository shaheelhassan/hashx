import hashlib
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

# --- HACHING ---
def generate_hash(data: str, algorithm: str = 'sha256', salt: str = '') -> str:
    """
    Generates a hash for the given string data using the specified algorithm.
    Supports salting.
    """
    if not data:
        return ""
    
    data_bytes = data.encode('utf-8')
    if salt:
        data_bytes += salt.encode('utf-8')
        
    if algorithm == 'md5':
        return hashlib.md5(data_bytes).hexdigest()
    elif algorithm == 'sha1':
        return hashlib.sha1(data_bytes).hexdigest()
    elif algorithm == 'sha256':
        return hashlib.sha256(data_bytes).hexdigest()
    elif algorithm == 'sha512':
        return hashlib.sha512(data_bytes).hexdigest()
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

def hash_file(file_path: str, algorithm: str = 'sha256') -> str:
    """
    Hashes a file's content in chunks to avoid memory issues.
    """
    if algorithm == 'md5':
        hasher = hashlib.md5()
    elif algorithm == 'sha1':
        hasher = hashlib.sha1()
    elif algorithm == 'sha256':
        hasher = hashlib.sha256()
    elif algorithm == 'sha512':
        hasher = hashlib.sha512()
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)
    return hasher.hexdigest()

# --- SYMMETRIC ENCRYPTION (AES-Fernet) ---
def generate_key_from_password(password: str, salt: bytes = None) -> tuple[bytes, bytes]:
    """
    Derives a secure URL-safe base64-encoded 32-byte key from a password using PBKDF2HMAC.
    Returns (key, salt). If salt is not provided, generates a new one.
    """
    if salt is None:
        salt = os.urandom(16)
        
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def encrypt_message(message: str, key: bytes) -> str:
    """
    Encrypts a message using Fernet (AES).
    """
    f = Fernet(key)
    return f.encrypt(message.encode()).decode()

def decrypt_message(encrypted_message: str, key: bytes) -> str:
    """
    Decrypts a Fernet (AES) encrypted message.
    """
    f = Fernet(key)
    return f.decrypt(encrypted_message.encode()).decode()

def encrypt_file(input_path: str, output_path: str, key: bytes):
    """
    Encrypts a file using Fernet.
    """
    f = Fernet(key)
    with open(input_path, 'rb') as file:
        file_data = file.read()
    encrypted_data = f.encrypt(file_data)
    with open(output_path, 'wb') as file:
        file.write(encrypted_data)

def decrypt_file(input_path: str, output_path: str, key: bytes):
    """
    Decrypts a file using Fernet.
    """
    f = Fernet(key)
    with open(input_path, 'rb') as file:
        encrypted_data = file.read()
    decrypted_data = f.decrypt(encrypted_data)
    with open(output_path, 'wb') as file:
        file.write(decrypted_data)

# --- ASYMMETRIC ENCRYPTION (RSA) ---
def generate_rsa_keypair():
    """
    Generates a private and public key pair.
    Returns tuple of (private_key_pem, public_key_pem)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return pem_private.decode(), pem_public.decode()

def rsa_encrypt(message: str, public_key_pem: str) -> str:
    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    encrypted = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode()

def rsa_decrypt(encrypted_b64: str, private_key_pem: str) -> str:
    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    encrypted_bytes = base64.b64decode(encrypted_b64)
    original_message = private_key.decrypt(
        encrypted_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return original_message.decode()

def rsa_sign(message: str, private_key_pem: str) -> str:
    """
    Signs a message using the private key and returns a base64 signature.
    """
    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()

def rsa_verify(message: str, signature_b64: str, public_key_pem: str) -> bool:
    """
    Verifies a signature using the public key.
    """
    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    signature = base64.b64decode(signature_b64)
    try:
        public_key.verify(
            signature,
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# --- GENERAL UTILITIES ---
def base64_encode_str(data: str) -> str:
    return base64.b64encode(data.encode()).decode()

def base64_decode_str(data: str) -> str:
    return base64.b64decode(data.encode()).decode()

def generate_strong_password(length: int = 16, include_symbols: bool = True) -> str:
    import string
    import random
    chars = string.ascii_letters + string.digits
    if include_symbols:
        chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
    return "".join(random.SystemRandom().choice(chars) for _ in range(length))
