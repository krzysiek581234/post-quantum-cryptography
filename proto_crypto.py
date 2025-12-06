import os
import random
import string

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SIGNATURE_ALGORITHMS = {"Dilithium": "ML-DSA-44", 
                        "Falcon": "Falcon-1024", 
                        "Cross": "cross-rsdp-256-balanced", 
                        "SPHINCS+": "SPHINCS+-SHAKE-128s-simple"
                        }
ENCRYPTION_ALGORITHMS = {"Kyber": "Kyber512"}


def proto_generate_keypair(algorithm: str):
    """
    Generuje parę kluczy dla wybranego algorytmu.
    Zwraca tuple (public_key, private_key) jako stringi.
    """
    if algorithm in ENCRYPTION_ALGORITHMS:
        print(f"Using {algorithm} algorithm")
        with oqs.KeyEncapsulation(ENCRYPTION_ALGORITHMS[algorithm]) as kem:
            pub = kem.generate_keypair()
            priv = kem.export_secret_key()
    
    elif algorithm in SIGNATURE_ALGORITHMS:
        print(f"Using {algorithm} algorithm")
        with oqs.Signature(SIGNATURE_ALGORITHMS[algorithm]) as signer:
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


def proto_sign(algorithm, data: str, private_key: str) -> bytes | None:
    from base64 import b64encode

    """
    Podpisuje dane.
    """

    if algorithm in SIGNATURE_ALGORITHMS:
        print(f"Using {algorithm} algorithm")
        with oqs.Signature(SIGNATURE_ALGORITHMS[algorithm], private_key) as signer:
            signature = signer.sign(data)

    else:
        return

    return b64encode(signature)


def proto_verify(algorithm, data: bytes, signature: str, public_key: bytes) -> bool | None:
    """
    Weryfikuje podpis.
    """
    from base64 import b64decode

    signature = b64decode(signature)

    if algorithm in SIGNATURE_ALGORITHMS:
        print(f"Using {algorithm} algorithm")
        with oqs.Signature(SIGNATURE_ALGORITHMS[algorithm]) as verifier:
            is_valid = verifier.verify(data, signature, public_key)
            return is_valid
    
    else:
        return
        