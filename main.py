from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from GUI_interface import create_sidebar, create_encryption_sidebar, create_sign_document_sidebar
from detect_USB import start_usb_detection_thread
from encription import decrypt_key, print_key
from frontend import create_root_window
from signature import create_xades_signature, verify_signature


def main():
    root = create_root_window()
    start_usb_detection_thread()
    create_sidebar(root, 0, 0, 3)
    create_encryption_sidebar(root, 0, 2, 8)
    create_sign_document_sidebar(root, 0, 3, 9)
    root.mainloop()


if __name__ == "__main__":
    main()
    # #private_key, hasz = decrypt_key(password="1234", path="keys/encrypted_private_key.bin")
    # private_key = rsa.generate_private_key(
    #     public_exponent=65537,
    #     key_size=4096,
    #     backend=default_backend()
    # )
    # public_key = private_key.public_key()
    # # print_key(private_key)
    # # print_key(public_key, private=False)
    # create_xades_signature('test/tekst.txt', private_key)
    # verify_signature( 'test/tekst.txt','test/signature.xml', public_key)