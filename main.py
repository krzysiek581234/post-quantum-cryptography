import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog
from PIL import Image, ImageOps, ImageDraw
import os
import time
import json
from detect_USB import start_usb_detection_thread
from proto_crypto import *
import threading
import traceback
import state

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class Sidebar(ctk.CTkFrame):
    def __init__(self, master, callback):
        super().__init__(master, width=220, corner_radius=0)
        self.callback = callback

        self.grid_propagate(False)

        # BRAND
        brand = ctk.CTkLabel(self, text="PQ-Crypto App",
                             text_color="#cbd5e1", font=("Segoe UI", 16, "bold"))
        brand.grid(row=0, column=0, pady=(20, 10), padx=20, sticky="w")

        # BUTTONS
        buttons = [
            ("Dashboard", "dashboard"),
            ("Keys", "keys"),
            ("Sign", "sign"),
            ("Verify", "verify"),
            ("Encrypt", "encrypt"),
            ("Decrypt", "decrypt"),
            # ("Settings", "settings"),
            ("Benchmarks", "benchmarks"),
            ("Help", "help"),
            ("Authors", "authors"),
        ]

        self.nav_buttons = {}

        for i, (label, page) in enumerate(buttons):
            b = ctk.CTkButton(
                self,
                text=label,
                width=180,
                height=32,
                corner_radius=8,
                fg_color="transparent",
                hover_color="#1d2635",
                anchor="w",
                command=lambda p=page: self.callback(p)
            )
            b.grid(row=i + 1, column=0, pady=4, padx=20, sticky="w")
            self.nav_buttons[page] = b

    def highlight(self, page):
        for p, btn in self.nav_buttons.items():
            if p == page:
                btn.configure(fg_color="#1a2332")
            else:
                btn.configure(fg_color="transparent")


class TopBar(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, corner_radius=0, fg_color="transparent")

        self.grid_columnconfigure(0, weight=1)

        self.title_label = ctk.CTkLabel(
            self, text="Dashboard",
            font=("Segoe UI", 22, "bold")
        )
        self.title_label.grid(row=0, column=0, padx=20, pady=(14, 0), sticky="w")

        self.desc_label = ctk.CTkLabel(
            self, text="Start here. Choose what you want to do.",
            font=("Segoe UI", 13), text_color="#94a3b8"
        )
        self.desc_label.grid(row=1, column=0, padx=20, pady=(0, 12), sticky="w")

    def update(self, title, desc):
        self.title_label.configure(text=title)
        self.desc_label.configure(text=desc)


class StatusBar(ctk.CTkFrame):
    def __init__(self, master, verify_callback):
        super().__init__(master, height=38, corner_radius=0)
        self.verify_callback = verify_callback
        self.grid_propagate(False)

        self.items = {
            "usb":  ctk.CTkLabel(self, text="USB: Not connected", text_color="#a1a1aa"),
            "pub":  ctk.CTkLabel(self, text="Public key: None",  text_color="#a1a1aa"),
            "priv": ctk.CTkLabel(self, text="Private key: None", text_color="#a1a1aa"),
            "algo": ctk.CTkLabel(self, text="Algo: Not Detected", text_color="#a1a1aa")
        }

        # grid labels in spaced columns
        self.items["usb"].grid( row=0, column=0, padx=10, pady=6, sticky="w")
        self.items["pub"].grid( row=0, column=1, padx=10, pady=6, sticky="w")
        self.items["priv"].grid(row=0, column=3, padx=10, pady=6, sticky="w")
        self.items["algo"].grid(row=0, column=5, padx=10, pady=6, sticky="w")

        # small frames for the button groups
        self.pub_btn_frame  = ctk.CTkFrame(self, fg_color="transparent")
        self.priv_btn_frame = ctk.CTkFrame(self, fg_color="transparent")

        self.pub_btn_frame.grid( row=0, column=2, padx=(2, 10))
        self.priv_btn_frame.grid(row=0, column=4, padx=(2, 10))

        # public key buttons
        self.btn_pub_down = ctk.CTkButton(self.pub_btn_frame, text="<", width=22, height=22,
                                          command=self.decrease_public)
        self.btn_pub_down.pack(side="left", padx=2)

        self.btn_pub_up = ctk.CTkButton(self.pub_btn_frame, text=">", width=22, height=22,
                                        command=self.increase_public)
        self.btn_pub_up.pack(side="left", padx=2)

        # private key buttons
        self.btn_priv_down = ctk.CTkButton(self.priv_btn_frame, text="<", width=22, height=22,
                                           command=self.decrease_private)
        self.btn_priv_down.pack(side="left", padx=2)

        self.btn_priv_up = ctk.CTkButton(self.priv_btn_frame, text=">", width=22, height=22,
                                         command=self.increase_private)
        self.btn_priv_up.pack(side="left", padx=2)


        self.verify = ctk.CTkButton(self.priv_btn_frame, text="Verify", width=70, height=22, command=self.verify_callback)
        self.verify.pack(side="left", padx=2)

    # ---------- Handlers for modification ----------
    def increase_public(self):
        state.skip_public_key += 1
        print("Increase public key skip:", state.skip_public_key)

    def decrease_public(self):
        state.skip_public_key = max(0, state.skip_public_key - 1)
        print("Decrease public key skip:", state.skip_public_key)

    def increase_private(self):
        state.skip_private_key += 1
        print("Increase private key skip:", state.skip_private_key)

    def decrease_private(self):
        state.skip_private_key = max(0, state.skip_private_key - 1)
        print("Decrease private key skip:", state.skip_private_key)

    # ---------- Your original update helpers ----------
    def update_item(self, key, text):
        self.items[key].configure(text=text)

    def set_private_key_status(self, unlocked: bool, path: str=None):
        if unlocked:
            self.items["priv"].configure(text=f"Private key: Unlocked {path}", text_color="#22d3ee")
        else:
            self.items["priv"].configure(text=f"Private key: Locked {path} 🔒 ", text_color="#eab308")

    def set_public_key_loaded(self, filename: str):
        self.items["pub"].configure(
            text=f"Public key: {filename}",
            text_color="#22d3ee"
        )

    def set_usb_status(self, connected: bool, path=None):
        if connected:
            self.items["usb"].configure(
                text=f"USB: Connected",
                text_color="#22ee66"
            )
        else:
            self.items["usb"].configure(
                text="USB: Not connected",
                text_color="#a81351"
            )


class MaskedInputDialog(ctk.CTkToplevel):
    def __init__(self, title="Input", text=""):
        super().__init__()
        self.title(title)

        self.label = ctk.CTkLabel(self, width=300, fg_color="transparent", text=text)
        self.label.pack(padx=20, pady=(20, 10))

        self.entry = ctk.CTkEntry(self, width=300, show="*")
        self.entry.pack(padx=20, pady=(0, 20))
        self.entry.focus()

        self.ok_button = ctk.CTkButton(self, width=120, text="Ok", command=self._ok_event)
        self.ok_button.pack(pady=(0, 20))

        self.protocol("WM_DELETE_WINDOW", self._cancel_event)
        self.bind("<Return>", self._ok_event)
        self.bind("<Escape>", self._cancel_event)
        self.resizable(False, False)

        self.grab_set()
        self.lift()
        self.input = None
        self.wait_window()

    def _ok_event(self, event=None):
        self.input = self.entry.get()
        self.destroy()

    def _cancel_event(self, event=None):
        self.input = None
        self.destroy()

    def get_input(self):
        return self.input


# ------------------------------
#   MAIN CONTENT PAGES
# ------------------------------

class DashboardPage(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master)
        self.build()

    def build(self):
        title = ctk.CTkLabel(
            self,
            text="Welcome to PQ-Crypto App",
            font=("Segoe UI", 22, "bold")
        )
        title.pack(pady=20)

        desc = (
            "Witaj w aplikacji chroniącej dane przed erą komputerów kwantowych.\n"
            "Poniżej znajdziesz krótkie wyjaśnienie stosowanych algorytmów:"
        )

        ctk.CTkLabel(
            self,
            text=desc,
            font=("Segoe UI", 14),
            text_color="#94a3b8",
            justify="center"
        ).pack(pady=10)

        container = ctk.CTkFrame(self, fg_color="transparent")
        container.pack(pady=15, padx=40, fill="both", expand=True)

        algorithms = [
            ("Kyber",
             "Algorytm KEM służący do bezpiecznej wymiany kluczy. "
             "Pozwala ustalić wspólny sekret do szyfrowania danych.\n\n"
             "Operacje w aplikacji:\n"
             "- generowanie kluczy,\n"
             "- enkapsulacja (tworzenie sekretu),\n"
             "- dekapsulacja,\n"
             "- szyfrowanie/odszyfrowanie pliku.\n"),

            ("Dilithium",
             "Standard NIST dla podpisów cyfrowych. Zapewnia autentyczność i "
             "integralność danych.\n\n"
             "Operacje w aplikacji:\n"
             "- generowanie kluczy,\n"
             "- podpis pliku,\n"
             "- weryfikacja podpisu.\n"),

            ("Picnic",
             "Podpis wykorzystujący zero-knowledge proofs. Chroni prywatność i "
             "jest odporny na ataki kwantowe.\n\n"
             "Operacje w aplikacji:\n"
             "- generowanie kluczy,\n"
             "- podpis pliku,\n"
             "- weryfikacja podpisu.\n"),

            ("XMSS",
             "Hash-based signature system z limitem użycia klucza. Wyjątkowo "
             "bezpieczny i stabilny.\n\n"
             "Operacje w aplikacji:\n"
             "- generowanie klucza z ograniczoną liczbą podpisów,\n"
             "- podpis pliku,\n"
             "- weryfikacja podpisu.\n"),

            ("SPHINCS+",
             "Hash-based podpis bez limitu użycia. Bardzo odporny na ataki "
             "post-kwantowe.\n\n"
             "Operacje w aplikacji:\n"
             "- generowanie kluczy,\n"
             "- podpis pliku,\n"
             "- weryfikacja podpisu.\n")
        ]

        for name, text in algorithms:
            card = ctk.CTkFrame(container, corner_radius=12)
            card.pack(fill="x", pady=6)

            ctk.CTkLabel(
                card,
                text=name,
                font=("Segoe UI", 17, "bold")
            ).pack(anchor="w", padx=14, pady=(8, 0))

            ctk.CTkLabel(
                card,
                text=text,
                wraplength=900,
                justify="left",
                text_color="#94a3b8",
                font=("Segoe UI", 13)
            ).pack(anchor="w", padx=14, pady=(2, 10))


class KeysPage(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master)
        self.build()

    def build(self):
        ctk.CTkLabel(self, text="Generate keys",
                     font=("Segoe UI", 18, "bold")).pack(pady=10)

        panel = ctk.CTkFrame(self, corner_radius=12)
        panel.pack(pady=10, padx=20, fill="x")

        ctk.CTkLabel(panel, text="Algorithm").pack(pady=4)
        self.algo = ctk.CTkOptionMenu(
            panel, 
            values=ALL_SUPPORTED_ALGORITHMS[:-3],
            command=self.algo_type
            )
        self.algo.pack(pady=4)

        self.kyber_mode_var = tk.StringVar(value="512")
        self.kyber_modes_frame = ctk.CTkFrame(panel, corner_radius=8, fg_color="transparent")
        ctk.CTkLabel(self.kyber_modes_frame, text="Kyber mode (key length)").pack(pady=4)

        self.mode_container = ctk.CTkFrame(self.kyber_modes_frame, fg_color="transparent")
        self.mode_container.pack(pady=4)

        for mode in ["512", "768", "1024"]:
            ctk.CTkRadioButton(
                self.mode_container,
                text=mode,
                variable=self.kyber_mode_var,
                value=mode
            ).pack(side="left", padx=10)

        self.kyber_modes_frame.pack_forget()

        ctk.CTkLabel(panel, text="Passphrase").pack(pady=4)
        self.pin1 = ctk.CTkEntry(panel, show="*")
        self.pin1.pack(pady=4)

        ctk.CTkLabel(panel, text="Confirm Passphrase").pack(pady=4)
        self.pin2 = ctk.CTkEntry(panel, show="*")
        self.pin2.pack(pady=4)

        ctk.CTkButton(panel, text="Generate key pair", command=self.generate_key).pack(pady=10)

        self.message_label = ctk.CTkLabel(self, text="", text_color="#22d3ee", font=("Segoe UI", 13, "bold"))
        self.message_label.pack(pady=8)

    def algo_type(self, choice):
        if choice == "Kyber":
            self.kyber_modes_frame.pack(pady=6, fill="x")
        else:
            self.kyber_modes_frame.pack_forget()

    def generate_key(self):
        algo = self.algo.get()
        pin1 = self.pin1.get()
        pin2 = self.pin2.get()

        if not pin1 or not pin2:
            self.message_label.configure(text="PIN fields cannot be empty!", text_color="#f87171")
            return
        if pin1 != pin2:
            self.message_label.configure(text="PINs do not match!", text_color="#f87171")
            return
        
        if algo == "Kyber":
            algo = f"Kyber{self.kyber_mode_var.get()}"

        pub, priv = proto_generate_keypair(algo)
        self.message_label.configure(
            text=f"Key pair generated!\nPublic: {pub[:16]}...\nPrivate: {priv[:16]}...",
            text_color="#22d3ee"
        )

        try:
            base_file_path = tk.filedialog.asksaveasfilename(
                filetypes=[("Pub Files", ".pub .key"), ("All Files", "*.*")],
                title="Save Key Pair (Select base filename)"
            )

            if base_file_path:
                # 2. Strip any extension the user might have typed to get the 'root' name
                # e.g., "C:/keys/mykey.txt" becomes "C:/keys/mykey"
                root_path = os.path.splitext(base_file_path)[0]

                # 3. Define the two separate paths with requested extensions
                pub_path = f"{root_path}.pub"
                priv_path = f"{root_path}.key"

                # 4. Write the PUBLIC key (.pem)
                with open(pub_path, "wb") as f:
                    f.write(algo.encode() + b' ' + pub)

                # 5. Write the PRIVATE key (.key)
                encrypted_priv = encrypt_private_key(priv, pin1)

                with open(priv_path, "wb") as f:
                    f.write(algo.encode() + b' ' + encrypted_priv)

                # 6. Update UI
                self.message_label.configure(
                    text=f"Success! Keys saved:\n{os.path.basename(pub_path)}\n{os.path.basename(priv_path)}",
                    text_color="#22d3ee"
                )

        except Exception as e:
            self.message_label.configure(text=f"Error saving files: {str(e)}", text_color="#f87171")


class SignPage(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master)
        self.app = master
        self.file_path = None
        self.key_path = None
        self.algorithm = None
        self.encrypted_key = None   # zaszyfrowany klucz z pliku
        self.private_key = None
        self.build()

    def choose_file(self):
        path = tk.filedialog.askopenfilename()
        if path:
            self.file_path = path
            self.file_label.configure(text=os.path.basename(path))

    def choose_key(self):
        """
        Ręczne wybranie klucza prywatnego z pliku .key
        – zapisujemy zaszyfrowany klucz i pokazujemy pole Passphrase.
        """
        path = tk.filedialog.askopenfilename(
            filetypes=[("Private key", ".key"), ("All Files", "*.*")],
            title="Select Key File"
        )
        if path:
            with open(path, "rb") as f:
                key = f.read()

            self.key_path = path
            algo_bytes, encrypted = key.split(b" ", 1)
            self.algorithm = algo_bytes.decode()
            self.encrypted_key = encrypted   # odszyfrujemy dopiero przy Sign

            self.key_label.configure(
                text=f"Key file: {os.path.basename(path)}\nUsing {self.algorithm} algorithm",
                text_color="#22d3ee"
            )

            # pokaż Passphrase tylko dla klucza z pliku
            self.passphrase_label.pack(pady=8)
            self.passphrase_entry.pack()
            self.passphrase_entry.delete(0, "end")

    def sign_file(self):
        if not self.file_path:
            self.message.configure(text="Musisz wybrać plik!", text_color="#f87171")
            return

        # 1. Priorytet: klucz z USB, jeśli odblokowany
        if self.app.key_unlocked and self.app.private_key_bytes:
            self.private_key = self.app.private_key_bytes
            self.algorithm = self.app.usb_algorithm

        # 2. Jeśli nie ma USB – używamy klucza z pliku .key
        elif self.encrypted_key is not None:
            pin = self.passphrase_entry.get()
            if not pin:
                self.message.configure(text="Passphrase jest wymagany!", text_color="#f87171")
                return

            try:
                self.private_key = decrypt_private_key(self.encrypted_key, pin)
            except Exception as e:
                self.message.configure(text=f"Niepoprawny passphrase: {e}", text_color="#f87171")
                return

        else:
            self.message.configure(
                text="Musisz odblokować klucz z USB lub wybrać plik .key!",
                text_color="#f87171"
            )
            return

        # --- wykonanie podpisu ---
        with open(self.file_path, "rb") as f:
            content = f.read()

        signature = proto_sign(self.algorithm, content, self.private_key)

        basename = os.path.basename(self.file_path)
        name, ext = os.path.splitext(basename)
        proposed = f"{name}_sign{ext}"

        save_path = tk.filedialog.asksaveasfilename(
            defaultextension=ext,
            initialfile=proposed
        )
        if save_path:
            with open(save_path, "wb") as sig:
                sig.write(content)
                sig.write(b"\n\n==========Begin " + self.algorithm.encode() + b" Signature==========\n")
                sig.write(signature)
                sig.write(b"\n==========End " + self.algorithm.encode() + b" Signature==========")

            self.message.configure(
                text=f"Podpis wygenerowany pomyślnie!\nZapisano do: {os.path.basename(save_path)}",
                text_color="#22d3ee"
            )

    def build(self):
        ctk.CTkLabel(self, text="Sign a document",
                     font=("Segoe UI", 18, "bold")).pack(pady=10)

        panel = ctk.CTkFrame(self, corner_radius=12)
        panel.pack(pady=10, padx=20, fill="x")

        # File selection
        ctk.CTkLabel(panel, text="Select File").pack(pady=6)
        ctk.CTkButton(panel, text="Choose file", command=self.choose_file).pack()
        self.file_label = ctk.CTkLabel(panel, text="No file selected", text_color="#94a3b8")
        self.file_label.pack(pady=4)

        # Private key selection
        ctk.CTkLabel(panel, text="Select Private Key file (.key)").pack(pady=6)
        ctk.CTkButton(panel, text="Choose file", command=self.choose_key).pack()
        self.key_label = ctk.CTkLabel(panel, text="No file selected", text_color="#94a3b8")
        self.key_label.pack(pady=4)

        # Passphrase – na start UKRYTE (tworzymy, ale nie pakujemy)
        self.passphrase_label = ctk.CTkLabel(panel, text="Passphrase")
        self.passphrase_entry = ctk.CTkEntry(panel, show="*")

        ctk.CTkButton(panel, text="Sign Document", command=self.sign_file).pack(pady=14)

        self.message = ctk.CTkLabel(self, text="", font=("Segoe UI", 13, "bold"))
        self.message.pack(pady=10)

    def refresh_usb_state(self):
        """
        Wywoływane, gdy klucz z USB zostanie wykryty / odblokowany.
        Jeśli USB jest aktywny – ukrywamy Passphrase (bo używamy tokena).
        """
        if self.app.key_unlocked and self.app.private_key_bytes:
            self.key_label.configure(
                text=f"Using USB key ({self.app.usb_algorithm})",
                text_color="#22d3ee"
            )
            self.passphrase_label.pack_forget()
            self.passphrase_entry.pack_forget()


class VerifyPage(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master)
        self.file_path = None
        self.sig_path = None
        self.pub_path = None
        self.algorithm = None
        self.build()

    def find_all(self, string: str, substring: str):
        '''Searches for all occurences of a substring in a string'''

        positions = []

        start = 0
        while True:
            start = string.find(substring, start)
            if start == -1:
                break
            positions.append(start)
            start += len(substring)
        return positions

    def choose_document(self):
        path = tk.filedialog.askopenfilename()
        if path:
            self.file_path = path
            self.doc_label.configure(text=os.path.basename(path))
            content = open(self.file_path, "rb").read()
            
            begin_positions = self.find_all(content.decode(), "==========Begin ")

            self.content = content[:begin_positions[-1] - 2]

            sig_split = content[begin_positions[-1]:].decode().split('\n')

            if len(sig_split) != 3:
                print("file coruppted: data appended")

            sig_begin, self.signature, sig_end = sig_split

            if len(sig_begin.split(' ')) != 3:
                print("file corrupted 1")

            sig_begin_start, begin_algorithm, sig_begin_end = sig_begin.split(' ')
            
            if sig_begin_start != "==========Begin":
                print("file corrupted 2")
            if sig_begin_end != "Signature==========":
                print("file corrupted 3")

            if len(sig_end.split(' ')) != 3:
                print("file corrupted 4")
            sig_end_start, end_algorithm, sig_end_end = sig_end.split(' ')

            if sig_end_start != "==========End":
                print("file corrupted 5")
            if sig_end_end != "Signature==========":
                print("file corrupted 6")

            if begin_algorithm != end_algorithm:
                print("file corrupted: algorithms don't match")
            else:
                self.algorithm = begin_algorithm

    def choose_public_key(self):
        path = tk.filedialog.askopenfilename(
                filetypes=[("Pub Files", ".pub"), ("All Files", "*.*")],
                title="Select Key File"
            )
        if path:
            with open(path, "rb") as f:
                key = f.read()
            self.key_path = path
            self.key_algorithm, self.public_key = key.split(b' ', 1)
            self.key_algorithm = self.key_algorithm.decode()
            self.pub_label.configure(text=f"Key file: {os.path.basename(path)}\nUsing {self.key_algorithm} algorithm") 

    def verify(self):
        if not self.file_path or not self.key_path:
            self.message.configure(text="Musisz wybrać plik, podpis i klucz!", text_color="#f87171")
            return

        if self.algorithm != self.key_algorithm:
            self.message.configure(text="Algorytm klucza nie pasuje do algorytmu podpisanego pliku!", text_color="#f87171")
            return
        
        result = proto_verify(self.algorithm, self.content, self.signature, self.public_key)

        if result:
            self.message.configure(text="Podpis jest poprawny!", text_color="#22d3ee")
        else:
            self.message.configure(text="Weryfikacja nie powiodła się!", text_color="#f87171")

    def build(self):
        ctk.CTkLabel(self, text="Verify Signature",
                     font=("Segoe UI", 18, "bold")).pack(pady=10)

        panel = ctk.CTkFrame(self, corner_radius=12)
        panel.pack(pady=10, padx=20, fill="x")

        # Document
        ctk.CTkButton(panel, text="Choose document", command=self.choose_document).pack(pady=6)
        self.doc_label = ctk.CTkLabel(panel, text="No file selected", text_color="#94a3b8")
        self.doc_label.pack()

        # Public key
        ctk.CTkButton(panel, text="Choose public key", command=self.choose_public_key).pack(pady=6)
        self.pub_label = ctk.CTkLabel(panel, text="No key selected", text_color="#94a3b8")
        self.pub_label.pack()

        # Verify
        ctk.CTkButton(panel, text="Verify", command=self.verify).pack(pady=10)

        self.message = ctk.CTkLabel(self, text="", font=("Segoe UI", 14, "bold"))
        self.message.pack(pady=10)


class EncryptPage(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master)
        self.file_path = None
        self.key_path = None
        self.build()

    def choose_file(self):
        path = tk.filedialog.askopenfilename()
        if path:
            self.file_path = path
            self.file_label.configure(text=os.path.basename(path))

    def choose_key(self):
        path = tk.filedialog.askopenfilename(
            filetypes=[("Pub Files", ".pub"), ("All Files", "*.*")],
            title="Select Public Key File"
            )
        if path:
            with open(path,"rb") as f:
                key = f.read()
            self.key_path = path
            self.algorithm, self.public_key = key.split(b' ', 1)
            self.algorithm = self.algorithm.decode()
            self.key_label.configure(text=f"Key file: {os.path.basename(path)}\nUsing {self.algorithm} algorithm")

    def encrypt_file(self):
        if not self.file_path or not self.key_path:
            self.message.configure(text="Musisz wybrać plik i klucz!", text_color="#f87171")
            return

        if self.algorithm not in ENCRYPTION_ALGORITHMS:
            self.message.configure(text="Wybrany klucz nie jest algorytmem szyfrujacym.", text_color="#f87171")
            return

        content = open(self.file_path, "rb").read()
        #private_key = open(self.key_path, "r", errors="ignore").read()

        encrypted = proto_encrypt(self.algorithm, content, self.public_key)
        if encrypted is None:
            self.message.configure(text="Blad szyfrowania - sprawdz klucz i algorytm.", text_color="#f87171")
            return

        basename = os.path.basename(self.file_path)
        name, ext = os.path.splitext(basename)
        proposed = f"{name}_encrypt{ext}"

        save_path = tk.filedialog.asksaveasfilename(
            defaultextension=ext,
            initialfile=proposed
        )
        if save_path:
            with open(save_path, "wb") as f:
                f.write(encrypted)
            self.message.configure(
                text=f"Plik zaszyfrowany pomyślnie!\nZapisano do: {os.path.basename(save_path)}",
                text_color="#22d3ee"
            )

    def build(self):
        ctk.CTkLabel(self, text="Encrypt File",
                     font=("Segoe UI", 18, "bold")).pack(pady=10)

        panel = ctk.CTkFrame(self, corner_radius=12)
        panel.pack(pady=10, padx=20, fill="x")

        ctk.CTkButton(panel, text="Choose file", command=self.choose_file).pack(pady=6)
        self.file_label = ctk.CTkLabel(panel, text="No file selected", text_color="#94a3b8")
        self.file_label.pack()

        ctk.CTkLabel(panel, text="Recipient public key").pack(pady=6)
        ctk.CTkButton(panel, text="Choose key", command=self.choose_key).pack()

        self.key_label = ctk.CTkLabel(panel, text="No key selected", text_color="#94a3b8")
        self.key_label.pack()

        ctk.CTkButton(panel, text="Encrypt", command=self.encrypt_file).pack(pady=10)

        self.message = ctk.CTkLabel(self, text="", font=("Segoe UI", 13, "bold"))
        self.message.pack(pady=10)


class DecryptPage(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master)
        self.file_path = None
        self.key_path = None
        self.private_key = None
        self.json_algorithm = None
        self.ciphertext = None
        self.nonce = None
        self.aes_payload = None
        self.app = master
        self.build()

    def refresh_usb_state(self):
        if self.app.key_unlocked and self.app.private_key_bytes:
            self.key_label.configure(
                text=f"Using USB key ({self.app.usb_algorithm})",
                text_color="#22d3ee"
            )

    def choose_encrypted(self):
        path = tk.filedialog.askopenfilename()
        if path:
            self.file_path = path
            self.file_label.configure(text=os.path.basename(path))
            try:
                with open(self.file_path, "rb") as f:
                    encrypted_json = f.read()

                packet = json.loads(encrypted_json)
                self.json_algorithm = packet["algorithm"]
                self.ciphertext = bytes.fromhex(packet["kem_ciphertex"])
                self.nonce = bytes.fromhex(packet["aes_nonce"])
                self.aes_payload = bytes.fromhex(packet["aes_payload"])
                self.message.configure(
                    text=f"Wczytano pakiet dla algorytmu {self.json_algorithm}",
                    text_color="#22d3ee"
                )
            except Exception as e:
                self.json_algorithm = None
                self.ciphertext = None
                self.nonce = None
                self.aes_payload = None
                self.message.configure(
                    text=f"Blad pliku: {e}",
                    text_color="#f87171"
                )

    def choose_key(self):
        path = tk.filedialog.askopenfilename(
                filetypes=[("Pub Files", ".key"), ("All Files", "*.*")],
                title="Select Private Key File"
            )
        if path:
            with open(path, "rb") as f:
                key = f.read()
            self.key_path = path
            self.algorithm, encrypted = key.split(b' ', 1)
            self.algorithm = self.algorithm.decode()

            pin = MaskedInputDialog(title="Unlock key", text="Enter passphrase:").get_input()
            if not pin:
                self.message.configure(text="Anulowano odblokowanie klucza.", text_color="#f87171")
                return

            try:
                self.private_key = decrypt_private_key(encrypted, pin)
            except Exception as e:
                self.message.configure(text=f"Nie udalo sie odblokowac klucza: {e}", text_color="#f87171")
                return

            self.key_label.configure(text=f"Key file: {os.path.basename(path)}\nUsing {self.algorithm} algorithm")

    def decrypt_file(self):
        if not self.file_path:
            self.message.configure(
                text="Musisz wybrać zaszyfrowany plik!",
                text_color="#f87171"
            )
            return

        # 2. Determine PRIVATE KEY SOURCE
        # --------------------------------
        # Jeśli klucz z USB jest odblokowany -> użyj go
        if self.app.key_unlocked and self.app.private_key_bytes:
            self.private_key = self.app.private_key_bytes
            self.algorithm = self.app.usb_algorithm

            self.key_label.configure(
                text=f"Using USB key ({self.algorithm})",
                text_color="#22d3ee"
            )

        elif not getattr(self, "key_path", None):
            self.message.configure(
                text="Musisz wybrać prywatny klucz lub odblokować USB key!",
                text_color="#f87171"
            )
            return


        if not all([self.json_algorithm, self.ciphertext, self.nonce, self.aes_payload]):
            self.message.configure(
                text="Najpierw wybierz poprawny zaszyfrowany plik.",
                text_color="#f87171"
            )
            return

        # 3. Sprawdzenie czy algorytm pliku zgadza się z algorytmem klucza
        if self.json_algorithm != self.algorithm:
            self.message.configure(
                text="Algorytm pliku nie pasuje do algorytmu klucza!",
                text_color="#f87171"
            )
            return


        try:
            # 4. Właściwe odszyfrowanie (Kyber KEM + AES-GCM)
            decrypted = proto_decrypt(
                self.algorithm,
                self.ciphertext,
                self.nonce,
                self.aes_payload,
                self.private_key
            )
        except Exception as e:
            self.message.configure(
                text=f"Błąd odszyfrowania: {e}",
                text_color="#f87171"
            )
            return


        basename = os.path.basename(self.file_path)
        name, ext = os.path.splitext(basename)
        proposed = f"{name}_decrypt{ext}"

        save_path = tk.filedialog.asksaveasfilename(
            defaultextension=ext,
            initialfile=proposed
        )

        if save_path:
            with open(save_path, "wb") as f:
                f.write(decrypted)

            self.message.configure(
                text=f"Plik odszyfrowany pomyślnie!\nZapisano do: {os.path.basename(save_path)}",
                text_color="#22d3ee"
            )

    def build(self):
        ctk.CTkLabel(self, text="Decrypt File",
                     font=("Segoe UI", 18, "bold")).pack(pady=10)

        panel = ctk.CTkFrame(self, corner_radius=12)
        panel.pack(pady=10, padx=20, fill="x")

        ctk.CTkButton(panel, text="Select encrypted file", command=self.choose_encrypted).pack(pady=6)
        self.file_label = ctk.CTkLabel(panel, text="No file selected", text_color="#94a3b8")
        self.file_label.pack()

        ctk.CTkButton(panel, text="Choose private key", command=self.choose_key).pack(pady=6)
        self.key_label = ctk.CTkLabel(panel, text="No key selected", text_color="#94a3b8")
        self.key_label.pack(pady=4)

        ctk.CTkButton(panel, text="Decrypt", command=self.decrypt_file).pack(pady=12)

        self.message = ctk.CTkLabel(self, text="", font=("Segoe UI", 13, "bold"))
        self.message.pack(pady=10)


# class SettingsPage(ctk.CTkFrame):
#     def __init__(self, master):
#         super().__init__(master)
#         self.build()

#     def build(self):
#         ctk.CTkLabel(self, text="Settings",
#                      font=("Segoe UI", 18, "bold")).pack(pady=10)

#         panel = ctk.CTkFrame(self, corner_radius=12)
#         panel.pack(pady=10, padx=20, fill="both")

#         ctk.CTkLabel(panel, text="Signature Algorithms").pack(pady=6)
#         for alg in SIGNATURE_ALGORITHMS.keys():
#             ctk.CTkCheckBox(panel, text=alg).pack()

#         ctk.CTkLabel(panel, text="Default").pack(pady=10)
#         ctk.CTkOptionMenu(panel, values=list(SIGNATURE_ALGORITHMS.keys())).pack()

class BenchmarkPage(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master)
        self.build()

    def build(self):
        # Title
        ctk.CTkLabel(self, text="Algorithm Benchmark",
                     font=("Segoe UI", 18, "bold")).pack(pady=10)

        # Settings Panel
        panel = ctk.CTkFrame(self, corner_radius=12)
        panel.pack(pady=10, padx=20, fill="x")

        # Algorithm Selection
        ctk.CTkLabel(panel, text="Select Algorithm to Benchmark").pack(pady=4)
        self.algo = ctk.CTkOptionMenu(panel, values=ALL_SUPPORTED_ALGORITHMS)
        self.algo.pack(pady=4)

        # Iterations Count
        ctk.CTkLabel(panel, text="Iterations (higher = more accurate)").pack(pady=4)
        self.iterations_entry = ctk.CTkEntry(panel)
        self.iterations_entry.insert(0, "50") 
        self.iterations_entry.pack(pady=4)

        # Start Button
        self.btn_start = ctk.CTkButton(panel, text="Start Benchmark", command=self.start_benchmark_thread)
        self.btn_start.pack(pady=15)

        # Results Area
        ctk.CTkLabel(self, text="Results:", anchor="w").pack(pady=(10, 0), padx=25, fill="x")
        
        self.results_text = ctk.CTkTextbox(self, height=250, font=("Consolas", 12))
        self.results_text.pack(pady=5, padx=20, fill="both", expand=True)
        self.results_text.configure(state="disabled")

    def log(self, message):
        """Helper to write to the text box in a thread-safe way"""
        self.results_text.configure(state="normal")
        self.results_text.insert("end", message + "\n")
        self.results_text.see("end")
        self.results_text.configure(state="disabled")

    def clear_log(self):
        self.results_text.configure(state="normal")
        self.results_text.delete("1.0", "end")
        self.results_text.configure(state="disabled")

    def start_benchmark_thread(self):
        # Disable button
        self.btn_start.configure(state="disabled", text="Running...")
        self.clear_log()
        
        # Start thread
        threading.Thread(target=self.run_benchmark, daemon=True).start()

    def run_benchmark(self):
        algo = self.algo.get()
        
        try:
            iterations = int(self.iterations_entry.get())
        except ValueError:
            self.log("Error: Iterations must be a number.")
            self.btn_start.configure(state="normal", text="Start Benchmark")
            return

        self.log(f"--- Starting Benchmark for {algo} ---")
        self.log(f"Iterations: {iterations}")
        self.log("Please wait...")

        try:
            # 1. Benchmark Key Generation
            # ---------------------------
            start_time = time.time()
            keys = [] 
            

            for _ in range(iterations):
                pub, priv = proto_generate_keypair(algo)
                keys.append((pub, priv))
                
            total_keygen_time = time.time() - start_time
            avg_keygen = (total_keygen_time / iterations) * 1000 # to ms

            self.log(f"\n[Key Generation]")
            self.log(f"Total time: {total_keygen_time:.4f}s")
            self.log(f"Avg time:   {avg_keygen:.2f} ms")
            self.log(f"Throughput: {iterations / total_keygen_time:.2f} ops/s")

            # 2. Benchmark Signing & Verifying (Signature Algos Only)
            # -------------------------------------------------------
            # Check if it's a signature algorithm supported by proto_sign
            
            if algo == "XMSS":
                self.log("\n[Error]")
                self.log("XMSS is not currently implemented in the crypto backend.")

            elif algo in SIGNATURE_ALGORITHMS.keys():
                # Prepare data - MUST be bytes for liboqs
                data_to_sign = b"This is a benchmark string to test post-quantum cryptography performance."
                
                # Use the last generated keypair
                pub_key, priv_key = keys[-1]

                # -- Benchmark Sign --
                start_time = time.time()
                signatures = []
                for _ in range(iterations):
                    sig = proto_sign(algo, data_to_sign, priv_key)
                    signatures.append(sig)
                
                total_sign_time = time.time() - start_time
                avg_sign = (total_sign_time / iterations) * 1000

                self.log(f"\n[Signing]")
                self.log(f"Total time: {total_sign_time:.4f}s")
                self.log(f"Avg time:   {avg_sign:.2f} ms")
                self.log(f"Throughput: {iterations / total_sign_time:.2f} ops/s")

                # -- Benchmark Verify --
                # Use the signatures generated above
                start_time = time.time()
                valid_count = 0
                for i in range(iterations):
                    # We cycle through signatures if we have many, or just use one
                    sig = signatures[i]
                    is_valid = proto_verify(algo, data_to_sign, sig, pub_key)
                    if is_valid:
                        valid_count += 1

                total_verify_time = time.time() - start_time
                avg_verify = (total_verify_time / iterations) * 1000

                self.log(f"\n[Verification]")
                self.log(f"Total time: {total_verify_time:.4f}s")
                self.log(f"Avg time:   {avg_verify:.2f} ms")
                self.log(f"Throughput: {iterations / total_verify_time:.2f} ops/s")
                self.log(f"Success rate: {valid_count}/{iterations}")

            elif algo in ENCRYPTION_ALGORITHMS.keys():
                # Prepare data
                data_to_encrypt = "This is a benchmark string for Kyber encryption."
                
                # Use the last generated keypair
                pub_raw, priv_raw = keys[-1]
                
                # Check types to prevent "decoding str is not supported" error
                if isinstance(pub_raw, bytes):
                    pub_str_content = pub_raw.decode('latin1')
                else:
                    pub_str_content = str(pub_raw)
                    
                if isinstance(priv_raw, bytes):
                    priv_str_content = priv_raw.decode('latin1')
                else:
                    priv_str_content = str(priv_raw)
                
                # Construct key strings in the format "Algorithm Key" 
                pub_key_str = f"{algo} {pub_str_content}"
                priv_key_str = f"{algo} {priv_str_content}"

                # -- Benchmark Encrypt --
                # Note: Kyber KEM encryption uses the Public Key to encapsulate/encrypt
                start_time = time.time()
                ciphertexts = []
                for _ in range(iterations):
                    # We pass the public key string to encrypt
                    ct = proto_encrypt(data_to_encrypt, pub_key_str)
                    ciphertexts.append(ct)
                
                total_enc_time = time.time() - start_time
                avg_enc = (total_enc_time / iterations) * 1000

                self.log(f"\n[Encryption]")
                self.log(f"Total time: {total_enc_time:.4f}s")
                self.log(f"Avg time:   {avg_enc:.2f} ms")
                self.log(f"Throughput: {iterations / total_enc_time:.2f} ops/s")

                # -- Benchmark Decrypt --
                start_time = time.time()
                for i in range(iterations):
                    # We pass the private key string to decrypt
                    # Use the ciphertext from the previous step
                    if ciphertexts[i] is not None:
                        res = proto_decrypt(ciphertexts[i], priv_key_str)

                total_dec_time = time.time() - start_time
                avg_dec = (total_dec_time / iterations) * 1000

                self.log(f"\n[Decryption]")
                self.log(f"Total time: {total_dec_time:.4f}s")
                self.log(f"Avg time:   {avg_dec:.2f} ms")
                self.log(f"Throughput: {iterations / total_dec_time:.2f} ops/s")

            self.log("\n--- Benchmark Complete ---")
                

        except Exception as e:
            self.log(f"\n[Error Occurred]\n{str(e)}")
            traceback.print_exc()

        # Re-enable button
        self.btn_start.configure(state="normal", text="Start Benchmark")


class HelpPage(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master)
        self.build()

    def build(self):
        ctk.CTkLabel(
            self,
            text="Help & Documentation",
            font=("Segoe UI", 18, "bold")
        ).pack(pady=10)

        text = (
            "Witaj w centrum pomocy aplikacji PQ-Crypto.\n\n"
            "Ta aplikacja chroni Twoje pliki przy użyciu algorytmów "
            "odpornych na ataki z wykorzystaniem komputerów kwantowych.\n\n"
            "Jak zacząć?\n"
            "• Keys — generuj pary kluczy zabezpieczone hasłem.\n"
            "• Sign — podpisuj dokumenty kluczem prywatnym.\n"
            "• Verify — sprawdzaj autentyczność podpisu.\n"
            "• Encrypt — szyfruj dane dla odbiorcy.\n"
            "• Decrypt — odszyfruj pliki używając klucza USB lub plikowego.\n\n"
            "Klucze USB są automatycznie wykrywane, a pasek stanu "
            "informuje o ich stanie i algorytmie.\n\n"
            "Jeśli aplikacja poprosi o hasło, oznacza to, że Twój klucz prywatny\n"
            "jest chroniony i wymaga autoryzacji do odblokowania.\n\n"
            "Benchmark — porównuje szybkość algorytmów, abyś mógł ocenić "
            "wydajność kryptografii post-kwantowej.\n\n"
            "Jeśli coś nie działa:\n"
            "• upewnij się, że pendrive jest podłączony,\n"
            "• sprawdź zgodność algorytmu klucza i pliku,\n"
            "• zweryfikuj poprawność wpisanego hasła.\n\n"
            "Eksperymentuj i rozwijaj się — bezpieczeństwo przyszłości "
            "budujesz już dziś!"
        )

        help_box = ctk.CTkTextbox(self, height=420, font=("Segoe UI", 13))
        help_box.pack(padx=20, pady=10, fill="both", expand=True)
        help_box.insert("1.0", text)
        help_box.configure(state="disabled")



class AuthorsPage(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        self.build()

    def round_image(self, path, size=140):
        """
        Tworzy okrągły profilowy avatar
        Zwraca obiekt CTkImage.        ctk.CTkLabel(
            card,
            text=name,
            font=("Segoe UI", 18, "bold")  # Increased from 15 to 18
        ).pack()        ctk.CTkLabel(
            card,
            text=name,
            font=("Segoe UI", 18, "bold")  # Increased from 15 to 18
        ).pack()
        """
        img = Image.open(path).convert("RGBA")
        img = img.resize((size, size), Image.LANCZOS)

        # maska kołowa
        mask = Image.new("L", (size, size), 0)
        draw = ImageDraw.Draw(mask)
        draw.ellipse((0, 0, size, size), fill=255)

        output = ImageOps.fit(img, (size, size), centering=(0.5, 0.5))
        output.putalpha(mask)

        return ctk.CTkImage(output, size=(size, size))

    def build(self):
        title = ctk.CTkLabel(
            self,
            text="Project Authors",
            font=("Segoe UI", 26, "bold")  # Larger title font
        )
        title.pack(pady=20)

        grid = ctk.CTkFrame(self, fg_color="transparent")
        grid.pack(pady=10, fill="both", expand=True)

        authors = [
            ("Krzysztof Madajczak", os.path.join("img", "KM.jpeg"),
             "GUI, architecture & core logic."),
            ("Julia Sadecka", os.path.join("img", "JS.jpeg"),
             "Kyber algorithm & design concepts."),
            ("Jakub Młocek", os.path.join("img", "JM.jpeg"),
             "Picnic & XMSS implementation."),
            ("Marcel Trzaskawka", os.path.join("img", "MT.jpeg"),
             "Dilithium & SPHINCS+ implementation."),
        ]

        for i, (name, img_path, desc) in enumerate(authors):
            card = ctk.CTkFrame(grid, width=320, height=340, corner_radius=14)
            card.grid(row=0, column=i, padx=20, pady=20, sticky="nsew")
            grid.grid_columnconfigure(i, weight=1)
            card.pack_propagate(False)

            if os.path.exists(img_path):
                avatar = self.round_image(img_path, size=160)
                ctk.CTkLabel(card, image=avatar, text="").pack(pady=10)
            else:
                ctk.CTkLabel(card, text="[missing photo]").pack(pady=10)

            ctk.CTkLabel(
                card,
                text=name,
                font=("Segoe UI", 18, "bold")
            ).pack()

            ctk.CTkLabel(
                card,
                text=desc,
                text_color="#94a3b8",
                font=("Segoe UI", 14),
                wraplength=260,
                justify="center"
            ).pack(pady=6)


# ------------------------------
#   MAIN APPLICATION
# ------------------------------

class PQApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.geometry("1920x1080")
        self.title("Post-Quantum Crypto App")
        self.private_key_bytes = None
        self.usb_algorithm = None
        self.key_unlocked = False
        self.public_key_bytes = None
        self.public_key_path = None

        # GRID LAYOUT
        self.grid_columnconfigure(1, weight=1)  
        self.grid_rowconfigure(1, weight=1)   # content
        self.grid_rowconfigure(0, weight=0)   # topbar
        self.grid_rowconfigure(2, weight=0)   # statusbar


        # SIDEBAR
        self.sidebar = Sidebar(self, self.switch_page)
        self.sidebar.grid(row=0, column=0, rowspan=3, sticky="nsw")

        # TOP BAR
        self.topbar = TopBar(self)
        self.topbar.grid(row=0, column=1, sticky="new")

        # MAIN CONTENT AREA
        self.pages = {
            "dashboard": DashboardPage(self),
            "keys": KeysPage(self),
            "sign": SignPage(self),
            "verify": VerifyPage(self),
            "encrypt": EncryptPage(self),
            "decrypt": DecryptPage(self),
            # "settings": SettingsPage(self),
            "benchmarks": BenchmarkPage(self),
            "help": HelpPage(self),
            "authors": AuthorsPage(self),
        }

        for p in self.pages.values():
            p.grid(row=1, column=1, sticky="nsew")
            p.grid_remove()

        # Show default
        self.switch_page("dashboard")

        # STATUS BAR
        self.statusbar = StatusBar(self, self.prompt_unlock_pin)
        self.statusbar.grid(row=2, column=1, sticky="sew")
        self.check_usb_event()


    def switch_page(self, page):
        for p in self.pages.values():
            p.grid_remove()

        self.pages[page].grid()

        self.sidebar.highlight(page)

        titles = {
            "dashboard": ("Dashboard", "Start here. Choose what you want to do."),
            "keys": ("Keys", "Generate and store PQ key pairs."),
            "sign": ("Sign", "Create post-quantum digital signatures."),
            "verify": ("Verify", "Check authenticity and integrity."),
            "encrypt": ("Encrypt", "Encrypt files using Kyber."),
            "decrypt": ("Decrypt", "Decrypt with USB private key."),
            # "settings": ("Settings", "Algorithms & configuration."),
            "benchmarks": ("Benchmarks", "Benchmark avaliable algorithms."),
            "help": ("Help", "Guides and troubleshooting."),
            "authors": ("Authors", "Team that created this project."),
        }

        t, d = titles[page]
        self.topbar.update(t, d)

    def check_usb_event(self):
        import state
        import os

        if state.usb_detected_event.is_set():
            detection = state.usb_path_queue.get()

            try:
                key_type, path, algo, key_bytes = detection
            except ValueError:
                print("[USB WARNING] Unexpected detection format:", detection)
                state.usb_detected_event.clear()
                self.after(1000, self.check_usb_event)
                return

            if key_type == "private":
                self.private_key_path = path
                self.usb_algorithm = algo
                self.private_key_bytes = key_bytes
                self.key_unlocked = False

                self.statusbar.set_usb_status(True, path)
                self.statusbar.update_item("algo", f"Algo: {algo}")
                self.statusbar.set_private_key_status(False, path)
                self.pages["sign"].refresh_usb_state()
                self.pages["decrypt"].refresh_usb_state()


            elif key_type == "public":
                self.public_key_path = path
                self.public_key_bytes = key_bytes
                filename = os.path.basename(path)
                self.statusbar.set_public_key_loaded(filename)

            state.usb_detected_event.clear()

        self.after(1000, self.check_usb_event)


    def clear_public_key(self):
        self.items["pub"].configure(
            text="Public key: None",
            text_color="#a1a1aa"
        )

    def prompt_unlock_pin(self):
        dialog = MaskedInputDialog(
            title="Unlock private key",
            text="Podaj Passphrase, aby odblokować klucz prywatny z USB:"
        )
        passphrase = dialog.get_input()

        if passphrase:
            try:
                decrypted = decrypt_private_key(self.private_key_bytes, passphrase)
                self.private_key_bytes = decrypted
                self.key_unlocked = True
                self.statusbar.set_private_key_status(True, self.private_key_path)
                self.pages["sign"].refresh_usb_state()
                self.pages["decrypt"].refresh_usb_state()
            except Exception:
                self.key_unlocked = False
                self.statusbar.set_private_key_status(False, self.private_key_path)
        else:
            self.key_unlocked = False
            self.statusbar.set_private_key_status(False,self.private_key_path)

    


if __name__ == "__main__":
    start_usb_detection_thread()
    app = PQApp()
    app.mainloop()
