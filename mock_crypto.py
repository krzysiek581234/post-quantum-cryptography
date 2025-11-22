import random
import string

def mock_generate_keypair(algorithm: str):
    """
    Symuluje generowanie pary kluczy dla wybranego algorytmu.
    Zwraca tuple (public_key, private_key) jako stringi.
    """
    pub = f"{algorithm.upper()}_PUB_" + ''.join(random.choices(string.ascii_uppercase + string.digits, k=32))
    priv = f"{algorithm.upper()}_PRIV_" + ''.join(random.choices(string.ascii_uppercase + string.digits, k=32))
    return pub, priv

def mock_encrypt(data: str, public_key: str):
    """
    Symuluje szyfrowanie danych.
    """
    return f"ENCRYPTED({data})_WITH_{public_key[:10]}..."

def mock_decrypt(data: str, private_key: str):
    """
    Symuluje deszyfrowanie danych.
    """
    return f"DECRYPTED({data})_WITH_{private_key[:10]}..."

def mock_sign(data: str, private_key: str):
    """
    Symuluje podpisywanie danych.
    """
    return f"SIGNATURE_OF({data})_BY_{private_key[:10]}..."

def mock_verify(data: str, signature: str, public_key: str):
    """
    Symuluje weryfikację podpisu.
    """
    # Zwraca True/False losowo (dla symulacji)
    return random.choice([True, False])