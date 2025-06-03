from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import os

# Derive key from password securely
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# Generate new salt
def generate_salt() -> bytes:
    return os.urandom(16)

# Encrypt message
def encrypt_message(message: str, password: str):
    salt = generate_salt()
    key = derive_key(password, salt)
    fernet = Fernet(key)
    encrypted = fernet.encrypt(message.encode())
    return salt + encrypted  # Prepend salt for later use

# Decrypt message
def decrypt_message(token: bytes, password: str):
    salt = token[:16]
    encrypted = token[16:]
    key = derive_key(password, salt)
    fernet = Fernet(key)
    return fernet.decrypt(encrypted).decode()

# Sample usage
if __name__ == "__main__":
    print("🔐 Secure Encryption Demo 🔐")
    user_password = input("Enter a strong password for encryption: ")
    sensitive_data = input("Enter sensitive information to encrypt: ")

    encrypted_data = encrypt_message(sensitive_data, user_password)
    print(f"\n[Encrypted]: {encrypted_data.hex()}")

    # Decrypt to verify
    try:
        decrypted = decrypt_message(encrypted_data, user_password)
        print(f"[Decrypted]: {decrypted}")
    except Exception as e:
        print("[!] Decryption failed:", e)
# Save encrypted data to file
with open("encrypted_data.bin", "wb") as f:
    f.write(encrypted_data)
