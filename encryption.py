"""
A simple GUI application for encrypting and decrypting files using AES‑256
(Fernet) with a password, built with Tkinter.

Usage:
  1. Install dependency:  pip install cryptography
  2. Run:               python file_encryptor_gui.py

Features:
  • Select any file from your system
  • Enter a password (masked)
  • Click **Encrypt** to create <filename>.enc
  • Click **Decrypt** to restore the original file (expects .enc files)

The same password must be used for encryption and decryption.
"""

import base64
import hashlib
import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet

def generate_key_from_password(password: str) -> bytes:
    """Derive a 32‑byte Fernet key from the given password using SHA‑256."""
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())


def encrypt_file(path: str, password: str) -> str:
    """Encrypt the file and return the path of the new .enc file."""
    key = generate_key_from_password(password)
    fernet = Fernet(key)

    with open(path, "rb") as infile:
        plaintext = infile.read()

    ciphertext = fernet.encrypt(plaintext)
    out_path = path + ".enc"
    with open(out_path, "wb") as outfile:
        outfile.write(ciphertext)

    return out_path


def decrypt_file(path: str, password: str) -> str:
    """Decrypt the .enc file and return the path of the restored file."""
    key = generate_key_from_password(password)
    fernet = Fernet(key)

    with open(path, "rb") as infile:
        ciphertext = infile.read()

    plaintext = fernet.decrypt(ciphertext)

    # Remove .enc suffix if present, otherwise append .dec
    out_path = path[:-4] if path.lower().endswith(".enc") else path + ".dec"
    with open(out_path, "wb") as outfile:
        outfile.write(plaintext)

    return out_path


# ---------- Tkinter GUI ---------- #

class EncryptorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("File Encryptor")
        self.geometry("420x240")
        self.resizable(False, False)

        self.file_path = tk.StringVar()

        # --- UI Layout --- #
        tk.Button(self, text="Select File", command=self.select_file, width=15).pack(pady=10)
        tk.Label(self, textvariable=self.file_path, wraplength=380, fg="blue").pack()

        tk.Label(self, text="Password:").pack(pady=(15, 5))
        self.password_entry = tk.Entry(self, show="*", width=30)
        self.password_entry.pack()

        btn_frame = tk.Frame(self)
        btn_frame.pack(pady=15)
        tk.Button(btn_frame, text="Encrypt", command=self.encrypt_selected, width=12).grid(row=0, column=0, padx=5)
        tk.Button(btn_frame, text="Decrypt", command=self.decrypt_selected, width=12).grid(row=0, column=1, padx=5)

    # ---------- UI Callbacks ---------- #

    def select_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.file_path.set(path)

    def encrypt_selected(self):
        self._process_file(encrypt_file, "Encrypted to")

    def decrypt_selected(self):
        self._process_file(decrypt_file, "Decrypted to")

    def _process_file(self, func, action_word):
        path = self.file_path.get()
        password = self.password_entry.get()

        if not path:
            messagebox.showwarning("Warning", "Please select a file first.")
            return
        if not password:
            messagebox.showwarning("Warning", "Please enter a password.")
            return

        try:
            out_path = func(path, password)
            messagebox.showinfo("Success", f"{action_word}:\n{out_path}")
        except Exception as exc:
            messagebox.showerror("Error", f"Operation failed:\n{exc}")

if __name__ == "__main__":
    app = EncryptorApp()
    app.mainloop()
