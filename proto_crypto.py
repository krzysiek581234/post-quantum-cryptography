import random
import string

import oqs

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
            alg_short_name = "Dilit"


    if algorithm == "Falcon":
        print(f"Using {algorithm} algorithm")
        with oqs.Signature("Falcon-1024") as signer:
            pub = signer.generate_keypair()
            priv = signer.export_secret_key() 
            alg_short_name = "Falco"


    if algorithm == "Cross":
        print(f"Using {algorithm} algorithm")
        with oqs.Signature("cross-rsdp-256-balanced") as signer:
            pub = signer.generate_keypair()
            priv = signer.export_secret_key() 
            alg_short_name = "Cross"

    else:
        print(f"Algorithm <{algorithm}> does not exist")

    return pub, priv, alg_short_name

def proto_encrypt(data: str, public_key: str):
    """
    Szyfruje dane.
    """
    algorithm = public_key[:5]
    public_key = public_key[6:]

    return f"ENCRYPTED({data})_WITH_{public_key[:10]}..."

def proto_decrypt(data: str, private_key: str):
    """
    Deszyfruje dane.
    """

    algorithm = private_key[:5]
    public_key = private_key[6:]
    return f"DECRYPTED({data})_WITH_{private_key[:10]}..."

def proto_sign(data: str, private_key: str):
    """
    Podpisuje dane.
    """
    algorithm = private_key[:5]
    private_key = private_key[6:]

    print(algorithm)
    print(private_key)

    if algorithm == "Falco": 
        print(f"Using Falcon algorithm")
        with oqs.Signature("Falcon-1024", private_key) as signer:
            signature = signer.sign(data)
            return signature
    elif algorithm == "Cross":
        print(f"Using Cross algorithm")
        with oqs.Signature("cross-rsdp-256-balanced", private_key) as signer:
            signature = signer.sign(data)
            return signature 
    elif algorithm == "Dilit":
        print(f"Using Dilithium algorithm")
        with oqs.Signature("ML-DSA-44", private_key) as signer:
            signature = signer.sign(data)
            return signature   



def proto_verify(data: str, signature: str, public_key: str):
    """
    Weryfikuje podpis.
    """
    algorithm = public_key[:5]
    public_key = public_key[6:]

    if algorithm == "Falco":
        print(f"Using Falcon algorithm")
        with oqs.Signature("Falcon-1024", public_key) as signer:
            is_valid = signer.verify(data, signature)
            return is_valid
        
    elif algorithm == "Cross": 
        print(f"Using Cross algorithm")
        with oqs.Signature("cross-rsdp-256-balanced", public_key) as signer:
            is_valid = signer.verify(data, signature)
            return is_valid
        
    elif algorithm == "Dilit":
        print(f"Using Dilithium algorithm")
        with oqs.Signature("ML-DSA-44", public_key) as signer:
            is_valid = signer.verify(data, signature)
            return is_valid  

