from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

from signature import sign_file, verify_signature
from tkinter import filedialog
from encription import *
from frontend import *
from pathlib import Path
import globals


def refresh_sidebar_if_usb_detected(root, sidebar, pendrive_label, feedback):

    if globals.usb_detected_event.is_set():
        globals.usb_detected_event.clear()
        private_key_path = globals.usb_path_queue.get()

        update_sign_document_sidebar(sidebar, pendrive_label, feedback)
    root.after(1000, refresh_sidebar_if_usb_detected, root, sidebar, pendrive_label, feedback)

def generate_private_key_and_public(label, pin='123'):
    if not pin:
        label.configure(text="password required")
        return
    else:
        label.configure(text="Keys Generated")
        private_key, public_key_temp = generate_rsa_keypair()
        encrypt_key(pin, private_key)
        if not Path("keys").exists():
            Path("keys").mkdir()
        save_private_key(private_key, "keys/not_encrypted_private_key.pem")
        # pri, hasz =decrypt_key(pin, "keys/not_encrypted_private_key.pem")
        # if private_key == pri:
        #     print("odszyfrowanie działa pomyślnie")
        save_public_key(public_key_temp, "keys/not_encrypted_public_key.pem")

def choose_xml():
    globals.XML_path = filedialog.askopenfilename()
    print(globals.XML_path)

def choose_the_document():
    globals.file_path = filedialog.askopenfilename()
    print(globals.file_path)

def choose_public_key():

    globals.path_public_key = filedialog.askopenfilename()
    globals.public_key = load_public_key(globals.path_public_key)
    #print_key(globals.public_key, private=False)
    print(globals.public_key)

def create_empty_label(parent, text="", row=0, column=0, padx=40, pady=(20, 10)):
    label = ctk.CTkLabel(parent, text=text)
    label.grid(row=row, column=column, padx=padx, pady=pady)
    return label


def create_sidebar(root, row, column, rowspan):
    sidebar = create_sidebar_frame(root, row, column, rowspan)
    label = create_label(sidebar, "Status", row=3)
    label.configure(text="Status")
    create_label(sidebar, "Generator - ETAP 1", row=0)
    pin_entry = create_entry(sidebar, placeholder_text="Enter PIN", row=1)
    create_button(sidebar, "Generate private key and public key", command=lambda: generate_private_key_and_public(label, pin_entry.get()), row=2)
    create_empty_label(sidebar, row=5)
    return sidebar


def check_password(password, private_key_path, label):
    if password == '' or password is None:
        print("password required")
        return
    private_key, hasz = decrypt_key(password,private_key_path)
    if not hasz:
        label.configure(text="Wrong password")
        return
    globals.GL_private_key = private_key
    if hasz.decode('utf-8')  == hashlib.sha256(password.encode()).hexdigest():
        label.configure(text="hasło poprawne")
        globals.correctPassword = True
        globals.key_password = password
    else:
        globals.correctPassword = False

def create_encryption_sidebar(root, row, column, rowspan):
    sidebar = create_sidebar_frame(root, row, column, rowspan, width=200)
    create_label(sidebar, "check Sign/Encryption", row=0)
    feedback = create_label(sidebar, "Encryption", row=1)
    create_button(sidebar, "public key", command=lambda: choose_public_key(), row=2)
    create_button(sidebar, "Choose the document to be Encrypted", command=lambda: encrypt_file(), row=3)
    #password_temp = create_entry(sidebar, placeholder_text="Enter PIN", row=3)
    #create_button(sidebar, "check password", command=lambda: check_password(password_temp.get(), globals.path_private_key, feedback), row=4)
    create_label(sidebar, "Check signature", row=5)
    create_button(sidebar, "choose document", command=lambda: choose_the_document(), row=6)
    create_button(sidebar, "choose XML", command=lambda: choose_xml(), row=7)
    create_button(sidebar, "Check signature", command=lambda: verify_signature(globals.file_path, globals.XML_path, globals.public_key), row=8)


def create_sign_document_sidebar(root, row, column, rowspan):
    sidebar = create_sidebar_frame(root, row, column, rowspan, width=200)
    create_label(sidebar, "Sign/Decryption", row=0)
    pendrive_label = create_label(sidebar, "Insert Pendrive", row=1, pady=(20, 10))


    feedback = create_label(sidebar, "", row=6, pady=(20, 10))
    refresh_sidebar_if_usb_detected(root, sidebar, pendrive_label, feedback)  # Start periodic check


def update_sign_document_sidebar(sidebar, pendrive_label, feedback):
    pendrive_label.configure(text="Decryption")
    create_button(sidebar, "Choose the document to be Decrypted", command=lambda: decrypt_file(), row=2)
    create_label(sidebar, "Sign", row=4)
    password_temp = create_entry(sidebar, placeholder_text="Enter PIN", row=5)
    create_button(sidebar, "check password", command=lambda: check_password(password_temp.get(), globals.path_private_key, feedback), row=7)
    create_button(sidebar, "Choose the document to be sign", command=lambda: sign_file(globals.key_password, globals.path_private_key, feedback), row=8)

    create_empty_label(sidebar, row=9)
    create_empty_label(sidebar,text=globals.path_private_key, row=10)

