import random
import string

import oqs

# print(oqs.get_enabled_sig_mechanisms())

# ["Kyber", "Dilithium", "Picnic", "XMSS", "SPHINCS++"]


def proto_generate_keypair(algorithm: str):
    """
    Generuje parę kluczy dla wybranego algorytmu.
    Zwraca tuple (public_key, private_key) jako stringi.
    """

    if algorithm == "Dilithium":
        print(f"Using {algorithm} algorithm")
        with oqs.Signature("ML-DSA-44") as signer, oqs.Signature("ML-DSA-44") as verifier:
            pub = signer.generate_keypair()
            priv = signer.export_secret_key()

    if algorithm == "Falcon":
        print(f"Using {algorithm} algorithm")
        with oqs.Signature("Falcon-1024") as signer, oqs.Signature("ML-DSA-44") as verifier:
            pub = signer.generate_keypair()
            priv = signer.export_secret_key()    
    else:
        print(f"Algorithm <{algorithm}> does not exist")

    # pub = f"{algorithm.upper()}_PUB_" + ''.join(random.choices(string.ascii_uppercase + string.digits, k=32))
    # priv = f"{algorithm.upper()}_PRIV_" + ''.join(random.choices(string.ascii_uppercase + string.digits, k=32))
    return pub, priv

def proto_encrypt(data: str, public_key: str):
    """
    Szyfruje dane.
    """

    if "Kyber" in public_key:
        pass
    elif "Dilithium" in public_key:
        pass
    return f"ENCRYPTED({data})_WITH_{public_key[:10]}..."

def proto_decrypt(data: str, private_key: str):
    """
    Deszyfruje dane.
    """
    return f"DECRYPTED({data})_WITH_{private_key[:10]}..."

def proto_sign(data: str, private_key: str):
    """
    Podpisuje dane.
    """
    return f"SIGNATURE_OF({data})_BY_{private_key[:10]}..."

def proto_verify(data: str, signature: str, public_key: str):
    """
    Weryfikuje podpis.
    """
    # Zwraca True/False losowo (dla symulacji)
    return random.choice([True, False])