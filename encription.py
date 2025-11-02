import base64
import xml.etree.ElementTree as ET
import os
import hashlib
from tkinter import filedialog

from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import globals
def print_key(key, private=True):
    if private:
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
    else:
        key_pem = key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
    print(key_pem)

def encrypt_key(password, private_key):
    salt = b'\x98A\xb9?J\xec\xe81v\x1c\xbb\xad\x1b\x85\x8a\x19\x89\x9d\x97t\xe6\xe7\xc3\x03\t"ht\xdda\xde\xcc'  # Można użyć get_random_bytes(32) w praktyce
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    cipher = AES.new(key, AES.MODE_CBC)
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    padded_private_key = pad(private_key_bytes, AES.block_size)
    cipher_data = cipher.encrypt(padded_private_key)
    hasz = hashlib.sha256(password.encode()).hexdigest()
    with open('keys/encrypted_private_key.bin', 'wb') as f:
        f.write(salt)
        f.write(hasz.encode())
        f.write(cipher.iv)
        f.write(cipher_data)

def decrypt_key(password, path= 'keys'):
    try:
        with open(path, 'rb') as f:
            salt = f.read(32)
            hasz = f.read(64)
            iv = f.read(16)
            cipher_data = f.read()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_padded_private_key = cipher.decrypt(cipher_data)
        private_key_bytes = unpad(decrypted_padded_private_key, AES.block_size)
        private_key = serialization.load_pem_private_key(
            private_key_bytes,
            password=None,
            backend=default_backend()
        )
        return private_key, hasz
    except Exception as e:
        print(f"Password wrong")
        return False, False


def load_public_key(filename):
    with open(filename, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return public_key


def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def save_private_key(private_key, filename):
    with open(filename, "wb") as key_file:
        key_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

def save_public_key(public_key, filename):
    with open(filename, "wb") as key_file:
        key_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )


def decrypt_file():
    if globals.correctPassword:
        print("Odszyfrowywanie")
        private_key, hasz = decrypt_key(password = globals.key_password, path = globals.path_private_key)
        if not hasz:
            return
        file_path = filedialog.askopenfilename()

        with open(file_path, 'rb') as f:
            ciphertext = f.read()

        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        directory, filename = os.path.split(file_path)
        new_filename = f"odszy_{filename}"
        new_file_path = os.path.join(directory, new_filename)
        print(f"Odszyfrowana wiadomość {plaintext}")
        with open(new_file_path, 'wb') as f:
             f.write(plaintext)
    else:
        print("Złe hasło")

def encrypt_file():
    if globals.public_key is None:
        print("YOU MUST SELECT PUBLIC KEY TO ENCRYPT")
        return
    print("SZYFROWANIE")
    file_path = filedialog.askopenfilename()
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    ciphertext = globals.public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    directory, filename = os.path.split(file_path)
    new_filename = f"szyfr_{filename}"
    new_file_path = os.path.join(directory, new_filename)

    with open(new_file_path, 'wb') as f:
        f.write(ciphertext)


# def test():
#     private_key, hasz = decrypt_key()
#     public_key = private_key.public_key()
#
#     with open('test.txt', 'rb') as f:
#         plaintext = f.read()
#     ciphertext = public_key.encrypt(
#         plaintext,
#         padding.OAEP(
#             mgf=padding.MGF1(algorithm=hashes.SHA256()),
#             algorithm=hashes.SHA256(),
#             label=None
#         )
#     )
#     with open('test.bin', 'wb') as f:
#         f.write(ciphertext)
#
#     with open('test.bin', 'rb') as f:
#         test_enc = f.read()
#
#
#     plaintext = private_key.decrypt(
#         test_enc,
#         padding.OAEP(
#             mgf=padding.MGF1(algorithm=hashes.SHA256()),
#             algorithm=hashes.SHA256(),
#             label=None
#         )
#     )
#     print(plaintext)