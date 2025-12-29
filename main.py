import json
import os
import secrets
import string
import tkinter as tk
from tkinter import messagebox, simpledialog, PhotoImage
import pyperclip

from gostcrypto import gostcipher, gosthash

DB_FILE = "passwords"

# backend logic
class gost_vault:
    def __init__(self, paster_pwd):
        # KDF
        streebog = gosthash.new('streebog256') # Стрибог
        salt = b'Aboba12345@' 
        streebog.update(salt + paster_pwd.encode('utf-8'))
        self.key = streebog.digest() # 32 byte(256 bit)
        
        # kuznechik block - 16 byte(128 bit)
        self.kuzn_size = 16

    def _pad(self, data):
        pad_len = self.kuzn_size - (len(data) % self.kuzn_size)
        return data + bytes([pad_len] * pad_len)

    def _unpad(self, data):
        if not data:
            return b""
        pad_len = data[-1]
        return data[:-pad_len]

    def encrypt_data(self, data):
        json_bytes = json.dumps(data).encode('utf-8')
        pad_data = self._pad(json_bytes)

        iv = os.urandom(self.kuzn_size)
        
        kuznechik = gostcipher.new('kuznechik', self.key, gostcipher.MODE_CBC, iv=iv)
        enc_data = kuznechik.encrypt(pad_data)
        
        return iv + enc_data

    def decrypt_data(self, enc_bytes):
        if len(enc_bytes) < self.kuzn_size:
            raise ValueError("файл поврежден")
        # парсинг данных из файла
        iv = enc_bytes[:self.kuzn_size]
        enc_data = enc_bytes[self.kuzn_size:]
        
        kuznechik = gostcipher.new('kuznechik', self.key, gostcipher.MODE_CBC, iv=iv)
        
        try:
            json_bytes = self._unpad(kuznechik.decrypt(enc_data))
            return json.loads(json_bytes.decode('utf-8'))
        except:
            return None


# GUI
class passwword_manager_app:
    def __init__(self):
        self.root = tk.Tk()
        self.root.withdraw()
        
        master_pwd = simpledialog.askstring("авторизация", "введите пароль:", show='*')
        
        if not master_pwd:
            self.root.destroy()
            return

        self.vault = gost_vault(master_pwd)
        
        self.curr_data = self.load_db()
        
        if self.curr_data is None:
            messagebox.showerror("---", "неверный пароль")
            self.root.destroy()
            return
        
        
        self.setup_ui()
        self.root.deiconify()
        self.root.mainloop()

    def load_db(self):
        if not os.path.exists(DB_FILE):
            return {}
        
        try:
            with open(DB_FILE, "rb") as f:
                content = f.read()
            return self.vault.decrypt_data(content)
        except Exception as e:
            print(f"error: {e}")
            return None

    def save_db(self):
        try:
            enc_bytes = self.vault.encrypt_data(self.curr_data)
            with open(DB_FILE, "wb") as f:
                f.write(enc_bytes)
            return True
        except Exception as e:
            messagebox.showerror("error", str(e))
            return False

    # UI handlers

    def generator(self):
        alph = string.ascii_letters + string.digits + string.punctuation
        pwd = ''.join(secrets.choice(alph) for _ in range(17))
        
        self.pwd_entry.delete(0, tk.END)
        self.pwd_entry.insert(0, pwd)
        pyperclip.copy(pwd)
        messagebox.showinfo("---", "пароль скопирован")

    def save_entry(self):
        web = self.web_entry.get()
        email = self.email_entry.get()
        pwd = self.pwd_entry.get()

        if len(web) == 0 or len(pwd) == 0:
            messagebox.showwarning("---", "впишите сайт и пароль.")
            return

        self.curr_data[web] = {
            "email": email,
            "password": pwd
        }

        if self.save_db():
            self.web_entry.delete(0, tk.END)
            self.pwd_entry.delete(0, tk.END)
            messagebox.showinfo("---", f"пароль сохранен")

    def find_pwd(self):
        web = self.web_entry.get()
        if web in self.curr_data:
            email = self.curr_data[web]["email"]
            pwd = self.curr_data[web]["password"]
            
            pyperclip.copy(pwd)
            messagebox.showinfo(web, f"email: {email}\nпароль: {pwd}")
        else:
            messagebox.showerror("---", f"данных не найдено")

    def setup_ui(self):
        self.root.title("менеджер паролей")
        self.root.config(padx=50, pady=50)

        tk.Label(text="website:").grid(column=0, row=1)
        tk.Label(text="email/login:").grid(column=0, row=2)
        tk.Label(text="password:").grid(column=0, row=3)

        self.web_entry = tk.Entry(width=35)
        self.web_entry.grid(column=1, row=1)
        self.web_entry.focus()

        self.email_entry = tk.Entry(width=35)
        self.email_entry.grid(column=1, row=2, columnspan=2, sticky="EW")
        self.email_entry.insert(0, "aboba@example.com")

        self.pwd_entry = tk.Entry(width=21) 
        self.pwd_entry.grid(column=1, row=3, sticky="EW")

        tk.Button(text="найти", command=self.find_pwd).grid(column=2, row=1, sticky="EW")
        tk.Button(text="сгенерировать", command=self.generator).grid(column=2, row=3, sticky="EW")
        tk.Button(text="добавить", width=36, command=self.save_entry).grid(column=1, row=4, columnspan=2, sticky="EW")

if __name__ == "__main__":
    app = passwword_manager_app()