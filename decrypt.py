from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def decrypt_message(token: bytes, password: str):
    salt = token[:16]
    encrypted = token[16:]
    key = derive_key(password, salt)
    fernet = Fernet(key)
    return fernet.decrypt(encrypted).decode()

if __name__ == "__main__":
    print("🔓 Decrypt Encrypted Data")
    password = input("Enter the password used for encryption: ")

    try:
        with open("encrypted_data.bin", "rb") as f:
            encrypted_data = f.read()

        decrypted = decrypt_message(encrypted_data, password)
        print(f"\n✅ Decrypted Message: {decrypted}")

    except Exception as e:
        print(f"[!] Error decrypting data: {e}")
