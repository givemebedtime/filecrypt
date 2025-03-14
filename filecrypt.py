import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

class FileEncryptor:  
    def __init__(self, password=None, algorithm="AES", key_size=32, iterations=100000): #ใช้กำหนดค่าพื้นฐานสำหรับการเข้ารหัส/ถอดรหัสไฟล์:
        self.password = password 
        self.algorithm = algorithm
        self.key_size = key_size
        self.iterations = iterations
        self.backend = default_backend() #สร้างออบเจ็กต์ default_backend จากไลบรารี Cryptography และเก็บไว้ในคุณสมบัติ

    def generate_key_from_password(self, password, salt): #สร้างคีย์เข้ารหัสจากรหัสผ่านและ salt
        kdf = PBKDF2HMAC( #สร้างคีย์ตามมาตรฐาน PBKDF2HMAC
            algorithm=hashes.SHA256(),
            length=self.key_size,
            salt=salt,
            iterations=self.iterations,
            backend=self.backend
        )
        return kdf.derive(password) #ส่งคืนคีย์ที่สามารถใช้สำหรับการเข้ารหัสหรือถอดรหัส

    def encrypt_file(self, file_name): #เข้ารหัสไฟล์ โดยใช้คีย์ที่สร้างจากรหัสผ่านและ salt
        salt = os.urandom(16)  #Salt คือ ข้อมูลแบบสุ่มที่เพิ่มลงไปก่อนกระบวนการแฮช เพื่อเพิ่มความปลอดภัยจากการโจมตีแบบเดา
        iv = os.urandom(16) #Initialization Vector คือค่าข้อมูลสุ่มที่ใช้ในกระบวนการเข้ารหัส เพื่อให้เวลาใช้รหัสเดิม คีย์จะไม่เหมือนเดิม
        key = self.generate_key_from_password(self.password.encode(), salt)
        cipher = Cipher(getattr(algorithms, self.algorithm)(key), modes.CBC(iv), backend=self.backend)

        with open(file_name, "rb") as file: #เปิดไฟล์ที่ต้องการเข้ารหัสในโหมดอ่าน (rb) และอ่านข้อมูลทั้งหมดเข้ามา
            file_data = file.read()

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(file_data) + padder.finalize() #ใช้ PKCS7 padding หรือ เติมข้อมูลให้ครบขนาดบล็อกของ AES เพื่อให้ข้อมูลพร้อมสำหรับการเข้ารหัส

        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize() #ใช้ encryptor เข้ารหัสข้อมูลที่ผ่านการ padding

        with open(file_name + ".encrypted", "wb") as file:
            file.write(salt + iv + encrypted_data) #สร้างไฟล์ใหม่ (ชื่อไฟล์เดิมต่อด้วย .encrypted)

    def decrypt_file(self, file_name): #ฟังก์ชันถอดรหัส
        with open(file_name, "rb") as file:
            data = file.read()

        salt = data[:16]
        iv = data[16:32]
        encrypted_data = data[32:]

        key = self.generate_key_from_password(self.password.encode(), salt)
        cipher = Cipher(getattr(algorithms, self.algorithm)(key), modes.CBC(iv), backend=self.backend) #ใช้รหัสผ่าน และ salt เพื่อสร้างคีย์สำหรับถอดรหัส

        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize() #สร้าง Cipher โดยใช้คีย์ที่สร้างขึ้น, อัลกอริธึมการเข้ารหัส และ iv

        unpadder = padding.PKCS7(128).unpadder()
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()  #ลบ Padding ออกจากข้อมูลที่ถอดรหัสแล้ว เพื่อคืนค่าให้เป็นข้อมูลต้นฉบับ

        if file_name.endswith(".encrypted"):
            new_file_name = file_name[:-10] #หากชื่อไฟล์ลงท้ายด้วย .encrypted จะตัดส่วนขยายนั้นออกเพื่อคืนชื่อไฟล์ต้นฉบับ
        else:
            new_file_name = file_name

        with open(new_file_name, "wb") as file:
            file.write(unpadded_data) #เขียนข้อมูลที่ถอดรหัสแล้ว (และลบ Padding) ลงในไฟล์ใหม่

# ส่วน GUI จากการใช้ tkinter
class FileEncryptorApp:
    def __init__(self, root):
        self.file_encryptor = None
        self.root = root
        self.root.title("FileCryptor GUI")
        self.root.configure(bg="#1f1e1e")
        self.root.resizable(False, False)

        # GUI Components
        self.password_info = tk.Label(root,bg="#1f1e1e",fg="lightblue",font=("Arial Rounded MT Bold",12) , text="Please Remember Password")
        self.password_info.grid(row=0, column=1,)
        
        self.password_label = tk.Label(root,bg="#1f1e1e",fg="lightblue",font=("Arial Rounded MT Bold",12) , text="Password :")
        self.password_label.grid(row=1, column=0, padx=10, pady=10)
        
        self.password_entry = tk.Entry(root, font=("Arial Rounded MT Bold",12),show="*", width=30)
        self.password_entry.grid(row=1, column=1, padx=10, pady=10)
        
        self.show_password_var = tk.BooleanVar()
        self.show_password_check = tk.Checkbutton(root,bg="#1f1e1e",fg="lightblue", text="Show Password",font=("Arial Rounded MT Bold",12) ,activebackground="#1f1e1e",activeforeground="lightblue", variable=self.show_password_var, command=self.toggle_password_visibility)
        self.show_password_check.grid(row=1, column=2, padx=10, pady=10)

        self.file_label = tk.Label(root,bg="#1f1e1e",font=("Arial Rounded MT Bold",12),fg="lightblue", text="Selected File:")
        self.file_label.grid(row=2, column=0, padx=10, pady=10)
        self.file_entry = tk.Entry(root, width=30,font=("Arial Rounded MT Bold",12), state='readonly')  # Set state to readonly
        self.file_entry.grid(row=2, column=1, padx=10, pady=10)

        self.browse_button = tk.Button(root, text="Browse",font=("Arial Rounded MT Bold",12),bg="lightblue",fg="darkblue",relief="flat",activebackground="aqua", command=self.browse_file)
        self.browse_button.grid(row=2, column=2, padx=10, pady=10)

        self.encrypt_button = tk.Button(root, text="Encrypt",font=("Arial Rounded MT Bold",12),bg="lightblue",fg="darkblue",relief="flat",activebackground="aqua", command=self.encrypt_file)
        self.encrypt_button.grid(row=3, column=0, padx=10, pady=10)

        self.decrypt_button = tk.Button(root, text="Decrypt",font=("Arial Rounded MT Bold",12),bg="lightblue",fg="darkblue",relief="flat",activebackground="aqua", command=self.decrypt_file)
        self.decrypt_button.grid(row=3, column=1, padx=10, pady=10)

        self.remove_checkbox = tk.IntVar()
        self.remove_file_checkbox = tk.Checkbutton(root,bg="#1f1e1e",font=("Arial Rounded MT Bold",12),fg="lightblue",activebackground="#1f1e1e",activeforeground="lightblue", text="Delete original file", variable=self.remove_checkbox)
        self.remove_file_checkbox.grid(row=4, column=0, columnspan=2, padx=10, pady=10)

    def toggle_password_visibility(self): #เปิดการมองเห็นพาสเวิร์ด
        if self.show_password_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")

    def browse_file(self): # เลือกไฟล์
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_entry.config(state='normal')  # Temporarily enable editing to insert file path
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, file_path)
            self.file_entry.config(state='readonly')  # Set back to readonly

    def encrypt_file(self):
        file_name = self.file_entry.get() #รับไฟล์และพาสเวิร์ด
        password = self.password_entry.get()

        if not file_name or not password:
            messagebox.showerror("Error", "Please provide both file and password.")
            return

        self.file_encryptor = FileEncryptor(password=password)
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
        file_name = self.file_entry.get() #รับไฟล์และพาสเวิร์ด
        password = self.password_entry.get()

        if not file_name or not password or not file_name.endswith(".encrypted"):
            messagebox.showerror("Error", "Please provide valid encrypted file and password.")
            return

        self.file_encryptor = FileEncryptor(password=password)
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


if __name__ == "__main__": #entrypoint สำหรับการสร้าง GUI เมื่อเปิดไฟล์
    root = tk.Tk()
    app = FileEncryptorApp(root)
    root.mainloop()
