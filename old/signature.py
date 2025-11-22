import base64
import xml.etree.ElementTree as ET
from datetime import datetime
from tkinter import filedialog
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os
import globals
from encription import decrypt_key


def sign_file(password,private_key_path, label):
    if not globals.correctPassword:
        label.configure(text="Wrong password")
        return
    else:
        label.configure(text="Signature complete")
        filepath = filedialog.askopenfilename()
        private_key, hasz = decrypt_key(password, private_key_path)
        if not hasz:
            return
        create_xades_signature(filepath, private_key)

def sign_document(document_hash, private_key):
    signature = private_key.sign(
        document_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def create_xades_signature(document_path, private_key):
    try:
        # Pobierz informacje o dokumencie
        document_size = os.path.getsize(document_path)
        document_extension = os.path.splitext(document_path)[-1]
        modification_date = datetime.fromtimestamp(os.path.getmtime(document_path)).isoformat()

        # Podpisz dokument
        with open(document_path, "rb") as file:
            document_content = file.read()

        document_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
        document_hash.update(document_content)
        calculated_digest = document_hash.finalize()

        print(f"Calculated digest (signing): {calculated_digest.hex()}")  # Debugowanie

        signature = sign_document(calculated_digest, private_key)
        print(f"Signature: {base64.b64encode(signature).decode()}")  # Debugowanie

        root = ET.Element("XAdES_Signature")
        document_info = ET.SubElement(root, "DocumentInfo")
        document_info.set("size", str(document_size))
        document_info.set("extension", document_extension)
        document_info.set("modification_date", modification_date)
        ET.SubElement(root, "SigningUserInfo", name="User A")
        ET.SubElement(root, "Timestamp").text = datetime.now().isoformat()
        ET.SubElement(root, "EncryptedHash").text = base64.b64encode(signature).decode()

        xml_tree = ET.ElementTree(root)
        directory = os.path.dirname(document_path)
        temp_path = os.path.join(directory, 'signature.xml')
        temp_path = os.path.normpath(temp_path)
        xml_tree.write(temp_path)
        print("Signature xml written to {}".format(temp_path))
        return signature

    except Exception as e:
        print("Error creating XAdES signature:", e)
        return None


def verify_signature(document_path, signature_xml_path, public_key):
    if public_key is None:
        print("Public key is None")
        return
    try:
        # Pobierz informacje o dokumencie
        document_size = os.path.getsize(document_path)
        document_extension = os.path.splitext(document_path)[-1]
        modification_date = datetime.fromtimestamp(os.path.getmtime(document_path)).isoformat()

        # Oblicz skrót dokumentu
        with open(document_path, "rb") as file:
            document_content = file.read()
        document_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
        document_hash.update(document_content)
        calculated_digest = document_hash.finalize()

        print(f"Calculated digest (verification): {calculated_digest.hex()}")  # Debugowanie

        # Odczytaj sygnaturę z pliku XML
        tree = ET.parse(signature_xml_path)
        root = tree.getroot()
        signature_base64 = root.find("EncryptedHash").text
        signature = base64.b64decode(signature_base64)

        #print(f"Signature (verification): {base64.b64encode(signature).decode()}")  # Debugowanie

        # Sprawdź ogólne informacje o dokumencie
        doc_info = root.find("DocumentInfo")
        if (doc_info.get("size") != str(document_size) or
            doc_info.get("extension") != document_extension or
            doc_info.get("modification_date") != modification_date):
            print(f"Expected size: {document_size}, extension: {document_extension}, modification_date: {modification_date}")
            print(f"Found size: {doc_info.get('size')}, extension: {doc_info.get('extension')}, modification_date: {doc_info.get('modification_date')}")
            raise ValueError("Document information mismatch.")

        # Weryfikacja podpisu przy użyciu klucza publicznego
        public_key.verify(
            signature,
            calculated_digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # Odczytaj informacje o użytkowniku podpisującym
        signing_user_info = root.find("SigningUserInfo")
        if signing_user_info is None or signing_user_info.get("name") != "User A":
            raise ValueError("Invalid signing user information.")

        # Odczytaj znacznik czasu
        timestamp = root.find("Timestamp").text
        print(f"Signature timestamp: {timestamp}")

        print("Signature verified successfully.")
    except Exception as e:
        print("Signature verification failed:", e)
