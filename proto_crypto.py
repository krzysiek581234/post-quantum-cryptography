import os
import random
import string
import json
from base64 import b64encode, b64decode
import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM



SIGNATURE_ALGORITHMS = {
    "Dilithium": "ML-DSA-44",
    "Falcon": "Falcon-1024",
    "Cross": "cross-rsdp-256-balanced",
    "SPHINCS+": "SPHINCS+-SHAKE-128s-simple",
}
ENCRYPTION_ALGORITHMS = ["Kyber", "Kyber512", "Kyber768", "Kyber1024"]
ALL_SUPPORTED_ALGORITHMS = list(SIGNATURE_ALGORITHMS.keys()) + list(
    ENCRYPTION_ALGORITHMS)



def proto_generate_keypair(algorithm: str) -> list[bytes, bytes] | None:
    """
    Generuje parę kluczy dla wybranego algorytmu.
    Zwraca tuple (public_key, private_key) jako stringi.
    """
    if algorithm in ENCRYPTION_ALGORITHMS:
        with oqs.KeyEncapsulation(algorithm) as kem:
            pub = kem.generate_keypair()
            priv = kem.export_secret_key()

    elif algorithm in SIGNATURE_ALGORITHMS:
        with oqs.Signature(SIGNATURE_ALGORITHMS[algorithm]) as signer:
            pub = signer.generate_keypair()
            priv = signer.export_secret_key()

    else:
        print(f"Algorithm <{algorithm}> does not exist")

    return pub, priv


def proto_encrypt(algorithm, data: str, public_key: str):
    """
    Szyfruje dane.
    """

    if algorithm in ENCRYPTION_ALGORITHMS:
        with oqs.KeyEncapsulation(algorithm) as kem:
            ciphertext, shared_secret = kem.encap_secret(public_key)
            aes_key = shared_secret[:32]
            aesgcm = AESGCM(aes_key)
            nonce = os.urandom(12)
            encrypted = aesgcm.encrypt(nonce, data, None)

            return json.dumps({
                "algorithm": algorithm,
                "kem_ciphertex": ciphertext.hex(),
                "aes_nonce": nonce.hex(),
                "aes_payload": encrypted.hex(),
            }).encode()
    else:
        print(f"Zla nazwa algorytmu: {algorithm}")

    # return f"ENCRYPTED({data})_WITH_{public_key[:10]}..."


def proto_decrypt(algorithm, ciphertext, nonce, aes_payload, private_key: str):
    """
    Deszyfruje dane.
    """
        
    
    with oqs.KeyEncapsulation(algorithm, private_key) as kem:
        shared_secret = kem.decap_secret(ciphertext)

    aes_key = shared_secret[:32]
    aesgcm = AESGCM(aes_key)

    try:
        decrypted = aesgcm.decrypt(nonce, aes_payload, None)
    except Exception as e:
        raise ValueError(f"Blad odszyfrowania: {e}")
    
    return decrypted


def proto_sign(algorithm, data: str, private_key: str) -> bytes | None:
    """
    Podpisuje dane.
    """

    if algorithm in SIGNATURE_ALGORITHMS:
        with oqs.Signature(SIGNATURE_ALGORITHMS[algorithm], private_key) as signer:
            signature = signer.sign(data)

    else:
        return

    return b64encode(signature)


def proto_verify(
    algorithm, data: bytes, signature: str, public_key: bytes
) -> bool | None:
    """
    Weryfikuje podpis.
    """

    signature = b64decode(signature)

    if algorithm in SIGNATURE_ALGORITHMS:
        with oqs.Signature(SIGNATURE_ALGORITHMS[algorithm]) as verifier:
            is_valid = verifier.verify(data, signature, public_key)
            return is_valid

    else:
        return

def _derive_key(passphrase: str, salt: bytes) -> bytes:
    """
    Converts passphrase + salt into strong AES key (32 bytes).
    """

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
    )

    return kdf.derive(passphrase.encode())


def encrypt_private_key(private_key: bytes, passphrase: str) -> bytes:
    """
    Encrypts private key using AES-GCM and password-derived key.
    Returns base64-encoded JSON package.
    """

    salt = os.urandom(16)
    key = _derive_key(passphrase, salt)

    aes = AESGCM(key)
    nonce = os.urandom(12)

    ciphertext = aes.encrypt(nonce, private_key, None)

    package = {
        "salt": b64encode(salt).decode(),
        "nonce": b64encode(nonce).decode(),
        "ciphertext": b64encode(ciphertext).decode(),
    }

    return b64encode(json.dumps(package).encode())


def decrypt_private_key(encrypted_priv_key: bytes, passphrase: str) -> bytes:
    """
    Decrypts base64-encoded encrypted private key with passphrase.
    """

    raw = json.loads(b64decode(encrypted_priv_key).decode())

    salt = b64decode(raw["salt"])
    nonce = b64decode(raw["nonce"])
    ciphertext = b64decode(raw["ciphertext"])

    key = _derive_key(passphrase, salt)

    aes = AESGCM(key)

    try:
        print("Trying to decrypt private key...")
        return aes.decrypt(nonce, ciphertext, None)
    except Exception:
        raise ValueError("Zła fraza lub uszkodzone dane")
