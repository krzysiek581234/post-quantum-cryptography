import os
import random
import string

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def proto_generate_keypair(algorithm: str):
    """
    Generuje parę kluczy dla wybranego algorytmu.
    Zwraca tuple (public_key, private_key) jako stringi.
    """

    if algorithm == "Kyber":
        print(f"Using {algorithm} algorithm")
        with oqs.KeyEncapsulation("Kyber512") as kem:
            pub = kem.generate_keypair()
            priv = kem.export_secret_key()

    elif algorithm == "Dilithium":
        print(f"Using {algorithm} algorithm")
        with oqs.Signature("ML-DSA-44") as signer:
            pub = signer.generate_keypair()
            priv = signer.export_secret_key()

    elif algorithm == "Falcon":
        print(f"Using {algorithm} algorithm")
        with oqs.Signature("Falcon-1024") as signer:
            pub = signer.generate_keypair()
            priv = signer.export_secret_key()

    elif algorithm == "Cross":
        print(f"Using {algorithm} algorithm")
        with oqs.Signature("cross-rsdp-256-balanced") as signer:
            pub = signer.generate_keypair()
            priv = signer.export_secret_key()

    else:
        print(f"Algorithm <{algorithm}> does not exist")

    return pub, priv


def proto_encrypt(data: str, public_key: str):
    """
    Szyfruje dane.
    """

    algorithm, public_key = public_key.split(" ", 1)
    algorithm = str(algorithm, encoding="utf-8")

    if algorithm == "Kyber":
        with oqs.KeyEncapsulation("Kyber512", public_key) as kem:
            ciphertext_kem, shared_secret = kem.encap_secret()
            aes_key = shared_secret[:32]
            aesgcm = AESGCM(aes_key)
            nonce = os.urandom(12)
            encrypted = aesgcm.encrypt(nonce, data.encode(), None)

            return {
                "kem_ciphertex": ciphertext_kem.hex(),
                "aes_nonce": nonce.hex(),
                "aes_payload": encrypted.hex(),
            }

    # return f"ENCRYPTED({data})_WITH_{public_key[:10]}..."


def proto_decrypt(data: str, private_key: str):
    """
    Deszyfruje dane.
    """

    algorithm, public_key = public_key.split(" ", 1)
    algorithm = str(algorithm, encoding="utf-8")

    return f"DECRYPTED({data})_WITH_{private_key[:10]}..."


def proto_sign(algorithm, data: str, private_key: str):
    from base64 import b64encode

    """
    Podpisuje dane.
    """

    if algorithm == "Falcon":
        print(f"Using Falcon algorithm")
        with oqs.Signature("Falcon-1024", private_key) as signer:
            signature = signer.sign(data)

    elif algorithm == "Cross":
        print(f"Using Cross algorithm")
        with oqs.Signature("cross-rsdp-256-balanced", private_key) as signer:
            signature = signer.sign(data)

    elif algorithm == "Dilithium":
        print(f"Using Dilithium algorithm")
        with oqs.Signature("ML-DSA-44", private_key) as signer:
            signature = signer.sign(data)
            print(b64encode(signature))
    else:
        return

    return b64encode(signature)


def proto_verify(algorithm, data: str, signature: str, public_key: bytes):
    """
    Weryfikuje podpis.
    """
    from base64 import b64decode

    signature = b64decode(signature)
    data = data.encode()

    if algorithm == "Falcon":
        print(f"Using Falcon algorithm")
        with oqs.Signature("Falcon-1024") as verifier:
            is_valid = verifier.verify(data, signature, public_key)
            return is_valid

    elif algorithm == "Cross":
        print(f"Using Cross algorithm")
        with oqs.Signature("cross-rsdp-256-balanced") as verifier:
            is_valid = verifier.verify(data, signature, public_key)
            return is_valid

    elif algorithm == "Dilithium":
        print(f"Using Dilithium algorithm")
        with oqs.Signature("ML-DSA-44") as verifier:
            is_valid = verifier.verify(data, signature, public_key)
            return is_valid
