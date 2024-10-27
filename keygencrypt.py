import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64

class FileEncryptor:
    def __init__(self, key=None, algorithm="AES", key_size=32, iterations=100000):
        self.key = key
        self.algorithm = algorithm
        self.key_size = key_size
        self.iterations = iterations
        self.backend = default_backend()

    def generate_key_from_password(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.key_size,
            salt=salt,
            iterations=self.iterations,
            backend=self.backend
        )
        return kdf.derive(password)

    def encrypt_file(self, file_name):
        salt = os.urandom(16)
        iv = os.urandom(16)
        key = self.key if isinstance(self.key, bytes) else self.generate_key_from_password(self.key.encode(), salt)
        cipher = Cipher(getattr(algorithms, self.algorithm)(key), modes.CBC(iv), backend=self.backend)

        with open(file_name, "rb") as file:
            file_data = file.read()

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(file_data) + padder.finalize()

        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        with open(file_name + ".encrypted", "wb") as file:
            file.write(salt + iv + encrypted_data)

    def decrypt_file(self, file_name):
        with open(file_name, "rb") as file:
            data = file.read()

        salt = data[:16]
        iv = data[16:32]
        encrypted_data = data[32:]

        key = self.key if isinstance(self.key, bytes) else self.generate_key_from_password(self.key.encode(), salt)
        cipher = Cipher(getattr(algorithms, self.algorithm)(key), modes.CBC(iv), backend=self.backend)

        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

        if file_name.endswith(".encrypted"):
            new_file_name = file_name[:-10]
        else:
            new_file_name = file_name

        with open(new_file_name, "wb") as file:
            file.write(unpadded_data)


class FileEncryptorApp:
    def __init__(self, root):
        self.file_encryptor = None
        self.root = root
        self.root.title("File Encryption/Decryption Tool")

        # GUI Components
        self.key_type_var = tk.StringVar(value="password")
        self.generated_key = None

        self.key_label = tk.Label(root, text="Enter Password or Generate Key:")
        self.key_label.grid(row=0, column=0, padx=10, pady=10)

        self.password_entry = tk.Entry(root, show="*", width=30)
        self.password_entry.grid(row=0, column=1, padx=10, pady=10)

        self.key_gen_button = tk.Button(root, text="Generate Key", command=self.generate_key)
        self.key_gen_button.grid(row=0, column=2, padx=10, pady=10)

        self.key_display_label = tk.Label(root, text="Generated Key (Base64):")
        self.key_display_label.grid(row=1, column=0, padx=10, pady=10)

        self.key_display_entry = tk.Entry(root, width=50, state='readonly')
        self.key_display_entry.grid(row=1, column=1, columnspan=2, padx=10, pady=10)

        self.custom_key_button = tk.Radiobutton(root, text="Use Custom Password", variable=self.key_type_var, value="password")
        self.custom_key_button.grid(row=2, column=0, columnspan=2, padx=10, pady=10)

        self.show_password_var = tk.BooleanVar()
        self.show_password_check = tk.Checkbutton(root, text="Show Password", variable=self.show_password_var, command=self.toggle_password_visibility)
        self.show_password_check.grid(row=0, column=3, padx=10, pady=10)

        self.file_label = tk.Label(root, text="Selected File:")
        self.file_label.grid(row=3, column=0, padx=10, pady=10)
        self.file_entry = tk.Entry(root, width=30, state='readonly')  # Set state to readonly
        self.file_entry.grid(row=3, column=1, padx=10, pady=10)

        self.browse_button = tk.Button(root, text="Browse", command=self.browse_file)
        self.browse_button.grid(row=3, column=2, padx=10, pady=10)

        self.encrypt_button = tk.Button(root, text="Encrypt", command=self.encrypt_file)
        self.encrypt_button.grid(row=4, column=0, padx=10, pady=10)

        self.decrypt_button = tk.Button(root, text="Decrypt", command=self.decrypt_file)
        self.decrypt_button.grid(row=4, column=1, padx=10, pady=10)

        self.remove_checkbox = tk.IntVar()
        self.remove_file_checkbox = tk.Checkbutton(root, text="Delete original file", variable=self.remove_checkbox)
        self.remove_file_checkbox.grid(row=5, column=0, columnspan=2, padx=10, pady=10)

    def toggle_password_visibility(self):
        if self.show_password_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_entry.config(state='normal')  # Temporarily enable editing to insert file path
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, file_path)
            self.file_entry.config(state='readonly')  # Set back to readonly

    def generate_key(self):
        self.generated_key = os.urandom(32)  # Generate a random 256-bit key
        self.key_display_entry.config(state='normal')  # Temporarily enable editing
        self.key_display_entry.delete(0, tk.END)  # Clear previous key
        self.key_display_entry.insert(0, base64.b64encode(self.generated_key).decode('utf-8'))  # Show key in Base64
        self.key_display_entry.config(state='readonly')  # Set back to readonly

    def encrypt_file(self):
        file_name = self.file_entry.get()
        password = self.password_entry.get()

        if not file_name or (self.key_type_var.get() == "password" and not password):
            messagebox.showerror("Error", "Please provide a valid file and password.")
            return

        key = self.generated_key if self.key_type_var.get() == "generate" else password.encode()

        self.file_encryptor = FileEncryptor(key=key)
        try:
            self.file_encryptor.encrypt_file(file_name)
            messagebox.showinfo("Success", f"{file_name} has been encrypted.")
            self.password_entry.delete(0, tk.END)  # Clear password entry after encryption
            self.file_entry.config(state='normal')  # Temporarily enable editing to insert file path
            self.file_entry.delete(0, tk.END)  # Clear file entry after encryption
            self.file_entry.config(state='readonly')  # Set back to readonly
            if self.remove_checkbox.get():
                os.remove(file_name)
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {e}")

    def decrypt_file(self):
        file_name = self.file_entry.get()
        password = self.password_entry.get()

        if not file_name or (self.key_type_var.get() == "password" and not password) or not file_name.endswith(".encrypted"):
            messagebox.showerror("Error", "Please provide valid encrypted file and password.")
            return

        key = self.generated_key if self.key_type_var.get() == "generate" else password.encode()

        self.file_encryptor = FileEncryptor(key=key)
        try:
            self.file_encryptor.decrypt_file(file_name)
            messagebox.showinfo("Success", f"{file_name} has been decrypted.")
            self.password_entry.delete(0, tk.END)  # Clear password entry after decryption
            self.file_entry.config(state='normal')  # Temporarily enable editing to insert file path
            self.file_entry.delete(0, tk.END)  # Clear file entry after decryption
            self.file_entry.config(state='readonly')  # Set back to readonly
            if self.remove_checkbox.get():
                os.remove(file_name)
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")


if __name__ == "__main__":
    root = tk.Tk()
    app = FileEncryptorApp(root)
    root.mainloop()
