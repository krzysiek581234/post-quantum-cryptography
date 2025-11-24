import customtkinter as ctk
import tkinter as tk
from PIL import Image, ImageOps, ImageDraw
import os
from proto_crypto import proto_generate_keypair

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
            ("Settings", "settings"),
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
    def __init__(self, master):
        super().__init__(master, height=38, corner_radius=0)
        self.grid_propagate(False)

        self.items = {
            "usb": ctk.CTkLabel(self, text="USB: Not connected", text_color="#a1a1aa"),
            "pub": ctk.CTkLabel(self, text="Public key: None", text_color="#a1a1aa"),
            "priv": ctk.CTkLabel(self, text="Private key: Locked", text_color="#a1a1aa"),
            "algo": ctk.CTkLabel(self, text="Algo: Dilithium3", text_color="#a1a1aa"),
        }

        for i, (k, widget) in enumerate(self.items.items()):
            widget.grid(row=0, column=i, padx=10, pady=6)

    def update_item(self, key, text):
        self.items[key].configure(text=text)


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

            ("SPHINCS++",
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
        self.algo = ctk.CTkOptionMenu(panel, values=[
            "Kyber", "Dilithium", "Picnic", "XMSS", "SPHINCS++"])
        self.algo.pack(pady=4)

        ctk.CTkLabel(panel, text="PIN").pack(pady=4)
        self.pin1 = ctk.CTkEntry(panel, show="*")
        self.pin1.pack(pady=4)

        ctk.CTkLabel(panel, text="Confirm PIN").pack(pady=4)
        self.pin2 = ctk.CTkEntry(panel, show="*")
        self.pin2.pack(pady=4)

        ctk.CTkButton(panel, text="Generate key pair", command=self.generate_key).pack(pady=10)

        self.message_label = ctk.CTkLabel(self, text="", text_color="#22d3ee", font=("Segoe UI", 13, "bold"))
        self.message_label.pack(pady=8)

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

        pub, priv = proto_generate_keypair(algo)
        self.message_label.configure(
            text=f"Key pair generated!\nPublic: {pub[:16]}...\nPrivate: {priv[:16]}...",
            text_color="#22d3ee"
        )


class SignPage(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master)
        self.file_path = None
        self.build()

    def choose_file(self):
        path = tk.filedialog.askopenfilename()
        if path:
            self.file_path = path
            self.file_label.configure(text=os.path.basename(path))
            

    def sign_file(self):
        from proto_crypto import mock_sign  # uses mock system  :contentReference[oaicite:2]{index=2}

        if not self.file_path:
            self.message.configure(text="Musisz wybrać plik!", text_color="#f87171")
            return

        algo = self.algo_option.get()
        pin = self.pin_entry.get()

        if not pin:
            self.message.configure(text="PIN jest wymagany!", text_color="#f87171")
            return

        with open(self.file_path, "r", errors="ignore") as f:
            content = f.read()
        

        signature = mock_sign(content, f"{algo}_PRIVATE_KEY")

        # Save signature
        basename = os.path.basename(self.file_path)
        name, ext = os.path.splitext(basename)
        proposed = f"{name}_sign{ext}"

        save_path = tk.filedialog.asksaveasfilename(
            defaultextension=ext,
            initialfile=proposed
        )
        if save_path:
            with open(save_path, "w") as sig:
                sig.write(signature)

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

        # Algorithm
        ctk.CTkLabel(panel, text="Algorithm").pack(pady=8)
        self.algo_option = ctk.CTkOptionMenu(panel, values=["Dilithium", "Picnic", "XMSS", "SPHINCS++"])
        self.algo_option.pack()

        # PIN
        ctk.CTkLabel(panel, text="PIN").pack(pady=8)
        self.pin_entry = ctk.CTkEntry(panel, show="*")
        self.pin_entry.pack()

        ctk.CTkButton(panel, text="Sign Document", command=self.sign_file).pack(pady=14)

        self.message = ctk.CTkLabel(self, text="", font=("Segoe UI", 13, "bold"))
        self.message.pack(pady=10)



class VerifyPage(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master)
        self.file_path = None
        self.sig_path = None
        self.pub_path = None
        self.build()

    def choose_document(self):
        path = tk.filedialog.askopenfilename()
        if path:
            self.file_path = path
            self.doc_label.configure(text=os.path.basename(path))

    def choose_signature(self):
        path = tk.filedialog.askopenfilename()
        if path:
            self.sig_path = path
            self.sig_label.configure(text=os.path.basename(path))

    def choose_public_key(self):
        path = tk.filedialog.askopenfilename()
        if path:
            self.pub_path = path
            self.pub_label.configure(text=os.path.basename(path))

    def verify(self):
        from proto_crypto import proto_verify  # proto verify  :contentReference[oaicite:3]{index=3}

        if not self.file_path or not self.sig_path or not self.pub_path:
            self.message.configure(text="Musisz wybrać plik, podpis i klucz!", text_color="#f87171")
            return

        # read files
        content = open(self.file_path, "r", errors="ignore").read()
        signature = open(self.sig_path, "r", errors="ignore").read()
        public_key = open(self.pub_path, "r", errors="ignore").read()

        result = proto_verify(content, signature, public_key)

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

        # Signature
        ctk.CTkButton(panel, text="Choose signature", command=self.choose_signature).pack(pady=6)
        self.sig_label = ctk.CTkLabel(panel, text="No signature selected", text_color="#94a3b8")
        self.sig_label.pack()

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
        path = tk.filedialog.askopenfilename()
        if path:
            self.key_path = path
            self.key_label.configure(text=os.path.basename(path))

    def encrypt_file(self):
        from proto_crypto import proto_encrypt

        if not self.file_path or not self.key_path:
            self.message.configure(text="Musisz wybrać plik i klucz!", text_color="#f87171")
            return

        content = open(self.file_path, "r", errors="ignore").read()
        public_key = open(self.key_path, "r", errors="ignore").read()

        encrypted = proto_encrypt(content, public_key)

        basename = os.path.basename(self.file_path)
        name, ext = os.path.splitext(basename)
        proposed = f"{name}_encrypt{ext}"

        save_path = tk.filedialog.asksaveasfilename(
            defaultextension=ext,
            initialfile=proposed
        )
        if save_path:
            with open(save_path, "w") as f:
                f.write(encrypted)
            self.message.configure(
                text=f"Plik zaszyfrowany pomyślnie!\nZapisano do: {os.path.basename(save_path)}",
                text_color="#22d3ee"
            )

    def build(self):
        ctk.CTkLabel(self, text="Encrypt File (Kyber)",
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
        self.build()

    def choose_encrypted(self):
        path = tk.filedialog.askopenfilename()
        if path:
            self.file_path = path
            self.file_label.configure(text=os.path.basename(path))

    def decrypt_file(self):
        from proto_crypto import proto_decrypt

        if not self.file_path:
            self.message.configure(text="Musisz wybrać zaszyfrowany plik!", text_color="#f87171")
            return

        pin = self.pin_entry.get()
        if not pin:
            self.message.configure(text="PIN jest wymagany!", text_color="#f87171")
            return

        encrypted = open(self.file_path, "r", errors="ignore").read()
        decrypted = proto_decrypt(encrypted, f"PRIVATE_KEY_{pin}")

        basename = os.path.basename(self.file_path)
        name, ext = os.path.splitext(basename)
        proposed = f"{name}_decrypt{ext}"

        save_path = tk.filedialog.asksaveasfilename(
            defaultextension=ext,
            initialfile=proposed
        )
        if save_path:
            with open(save_path, "w") as f:
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

        self.pin_entry = ctk.CTkEntry(panel, placeholder_text="Enter PIN", show="*")
        self.pin_entry.pack(pady=6)

        ctk.CTkButton(panel, text="Decrypt", command=self.decrypt_file).pack(pady=12)

        self.message = ctk.CTkLabel(self, text="", font=("Segoe UI", 13, "bold"))
        self.message.pack(pady=10)



class SettingsPage(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master)
        self.build()

    def build(self):
        ctk.CTkLabel(self, text="Settings",
                     font=("Segoe UI", 18, "bold")).pack(pady=10)

        panel = ctk.CTkFrame(self, corner_radius=12)
        panel.pack(pady=10, padx=20, fill="both")

        ctk.CTkLabel(panel, text="Signature Algorithms").pack(pady=6)
        ctk.CTkCheckBox(panel, text="Dilithium3").pack()
        ctk.CTkCheckBox(panel, text="Picnic").pack()
        ctk.CTkCheckBox(panel, text="XMSS").pack()
        ctk.CTkCheckBox(panel, text="SPHINCS++").pack()

        ctk.CTkLabel(panel, text="Default").pack(pady=10)
        ctk.CTkOptionMenu(panel, values=[
            "Dilithium3", "XMSS", "SPHINCS++"]).pack()


class HelpPage(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master)
        self.build()

    def build(self):
        ctk.CTkLabel(self, text="Help & Documentation",
                     font=("Segoe UI", 18, "bold")).pack(pady=10)

        ctk.CTkLabel(self, text="Guides, troubleshooting, explanation of algorithms.",
                     text_color="#94a3b8").pack(pady=10)


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
            "settings": SettingsPage(self),
            "help": HelpPage(self),
            "authors": AuthorsPage(self),
        }

        for p in self.pages.values():
            p.grid(row=1, column=1, sticky="nsew")
            p.grid_remove()

        # Show default
        self.switch_page("dashboard")

        # STATUS BAR
        self.statusbar = StatusBar(self)
        self.statusbar.grid(row=2, column=1, sticky="sew")

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
            "settings": ("Settings", "Algorithms & configuration."),
            "help": ("Help", "Guides and troubleshooting."),
            "authors": ("Authors", "Team that created this project."),
        }

        t, d = titles[page]
        self.topbar.update(t, d)


if __name__ == "__main__":
    app = PQApp()
    app.mainloop()

    pub, priv = proto_generate_keypair("Kyber")
    print(pub, priv)
