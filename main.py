import json
import os
import secrets
import string
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox, simpledialog, PhotoImage
import pyperclip
import hmac
import ctypes
import gc
from linux_keyring import KeyringManager, KEY_SPEC_PROCESS_KEYRING

from gostcrypto import gostcipher, gosthash, gosthmac, gostpbkdf

DB_FILE = "passwords"
GEN_FILE = "generator"

#ram cleaner
def data_clean(data):
    if isinstance(data, bytearray):
        # (c_char * len)
        buffer = (ctypes.c_char * len(data)).from_buffer(data)
        # Зануляем буфер
        ctypes.memset(buffer, 0, len(data))
    del data
    gc.collect()

# backend logic
class gost_vault:
    def __init__(self, paster_pwd, salt=None):
        if salt is None:
            self.salt = os.urandom(32)
        else:
            self.salt = salt

        # PBKDF
        pbkdf_obj = gostpbkdf.new(password=paster_pwd, salt=self.salt, counter=10**3)
        key_mats = pbkdf_obj.derive(64)

        self.key_enc = key_mats[:32] #32 bytes
        self.key_mac = key_mats[32:]
        #передача ключей на хранение ядру
        self.key_enc_id = KeyringManager.add("gost_enc", self.key_enc, KEY_SPEC_PROCESS_KEYRING)
        self.key_mac_id = KeyringManager.add("gost_mac", self.key_mac, KEY_SPEC_PROCESS_KEYRING)

        data_clean(self.key_enc)
        data_clean(self.key_mac)

        # kuznechik block - 16 byte(128 bit), mac size 32 bytes(256 bit)
        self.kuzn_size = 16
        self.mac_size = 32

    #получение ключей из ядра
    def _get_key_enc(self):
        return KeyringManager.read(self.key_enc_id)
    def _get_key_mac(self):
        return KeyringManager.read(self.key_mac_id)

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
        
        self.key_enc = self._get_key_enc()
        try:
            kuznechik = gostcipher.new('kuznechik', self.key_enc, gostcipher.MODE_CBC, iv=iv)
            enc_data = kuznechik.encrypt(pad_data)
        finally:
            data_clean(self.key_enc)
        
        # создание имитовставки (HMAC)
        data = iv + enc_data
        self.key_mac = self._get_key_mac()
        try:
            if self.mac_size == 32:
                hmac_obj = gosthmac.new('HMAC_GOSTR3411_2012_256', self.key_mac, data=data)
            elif self.mac_size == 64:
                hmac_obj = gosthmac.new('HMAC_GOSTR3411_2012_512', self.key_mac, data=data)
            mac = hmac_obj.digest()
        finally:
            data_clean(self.key_mac)

        return iv + mac + enc_data

    def decrypt_data(self, enc_bytes):
        data_len = self.kuzn_size + 16 + self.mac_size # data 1 block(16 bytes) + iv(16 bytes) + mac(32 bytes) 
        if len(enc_bytes) < data_len:
            raise ValueError("файл поврежден")
        # парсинг данных из файла
        iv = enc_bytes[:self.kuzn_size]
        mac = enc_bytes[self.kuzn_size:(self.kuzn_size+self.mac_size)]
        enc_data = enc_bytes[(self.kuzn_size+self.mac_size):]
        self.key_mac = self._get_key_mac()
        self.key_enc = self._get_key_enc()
        #data check
        data = iv + enc_data
        if self.mac_size == 32:
            hmac_obj = gosthmac.new('HMAC_GOSTR3411_2012_256', self.key_mac, data=data)
        elif self.mac_size == 64:
            hmac_obj = gosthmac.new('HMAC_GOSTR3411_2012_512', self.key_mac, data=data)
        calc_mac = hmac_obj.digest()

        # Encrypt-then-MAC для защиты от Chosen-Ciphertext Attacks (CCA)
        if not(hmac.compare_digest(calc_mac, mac)):
            raise ValueError("Неправильный пароль или данные повреждены")
        
        kuznechik = gostcipher.new('kuznechik', self.key_enc, gostcipher.MODE_CBC, iv=iv)
        data_clean(self.key_enc)
        data_clean(self.key_mac)
        try:
            return json.loads(self._unpad(kuznechik.decrypt(enc_data)).decode('utf-8'))
        except:
            return None
    #шифрование отдельных данных
    def encrypt_bytes(self, data):
        
        self.key_enc = self._get_key_enc()
        try:
            kuznechik = gostcipher.new('kuznechik', self.key_enc, gostcipher.MODE_ECB)
            return kuznechik.encrypt(self._pad(data))
        finally:
            data_clean(self.key_enc)

    #расшифровываем отдельные данные
    def decrypt_bytes(self, enc_bytes):
        self.key_enc = self._get_key_enc()
        try:
            kuznechik = gostcipher.new('kuznechik', self.key_enc, gostcipher.MODE_ECB)
            return self._unpad(kuznechik.decrypt(enc_bytes)).decode("utf-8")
        finally:
            data_clean(self.key_enc)
        
    def cleanup(self):
        try:
            KeyringManager.revoke(self.key_enc_id)
            KeyringManager.revoke(self.key_mac_id)
        except:
            pass

#secure tk entry
class SecureEntry(tk.Entry):
    def __init__(self, parent, mask_input=True, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.pwd_buffer = bytearray() # pwd buffer
        self.mask_input = mask_input #скрывать звездами или нет
        
        self.bind('<Key>', self.on_key_press)
        self.bind('<Control-c>', lambda e: "break")

    def on_key_press(self, event):
        key = event.keysym

        if key == ('Return', 'Tab'):
            return None
        
        if key == 'BackSpace':
            if len(self.pwd_buffer) > 0:
                self.pwd_buffer.pop()
                if self.mask_input:
                    # Удаляем последнюю звездочку
                    current_text = self.get()
                    self.delete(len(current_text)-1, tk.END)
                else:
                    # Позволяем Tkinter удалить символ
                    return None 
            return "break" if self.mask_input else None
        
        if len(event.char) == 0 or ord(event.char) < 32: #не обрабатываем служебные клавиши
            return None 

        # Добавляем символ в буфер
        char_bytes = event.char.encode('utf-8')
        self.pwd_buffer.extend(char_bytes)

        if self.mask_input:
            self.insert(tk.END, '*')
            return "break"
        else:
            return None


    def get_bytes(self):
        return self.pwd_buffer

    def clear(self):
        if self.pwd_buffer:
            # Зануляем буфер
            buf_len = len(self.pwd_buffer)
            buffer = (ctypes.c_char * buf_len).from_buffer(self.pwd_buffer)
            ctypes.memset(buffer, 0, buf_len)
            del self.pwd_buffer
            self.pwd_buffer = bytearray()
            self.delete(0, tk.END)
    def set_text(self, text):
        self.clear()
        self.pwd_buffer.extend(text.encode('utf-8'))
        self.delete(0, tk.END)
        if self.mask_input:
            self.insert(0, "*" * len(text))
        else:
            self.insert(0, text)

# GUI
class passwword_manager_app:
    def __init__(self):
        self.root = tk.Tk()
        self.root.withdraw()
        
        self.pwd_buffer = None
        
        auth_window = tk.Toplevel(self.root)
        auth_window.title("авторизация")
        auth_window.config(padx=50, pady=20)
        tk.Label(auth_window, text="введите пароль:").pack(pady=10)
        
        # наш виджет
        secure_entry = SecureEntry(auth_window, width=20)
        secure_entry.pack(pady=5)
        secure_entry.focus_set()
        
        # получаем мастер пароль
        def on_submit(event=None):
            self.pwd_buffer = secure_entry.get_bytes()[:] 
            secure_entry.clear() 
            auth_window.destroy()
            
        btn = tk.Button(auth_window, text="OK", command=on_submit)
        btn.pack(pady=10)
        auth_window.bind('<Return>', on_submit)
        
        self.root.wait_window(auth_window)
        
        if not self.pwd_buffer:
            self.root.destroy()
            return

        try:
            salt = None
            if os.path.exists(DB_FILE):
                with open(DB_FILE, "rb") as f:
                    header = f.read(32)
                    if len(header) == 32:
                        salt = header

            self.vault = gost_vault(self.pwd_buffer, salt=salt)
        
            self.curr_data = self.load_db()
        except Exception as e:
            messagebox.showerror("Ошибка", e)
        finally:
            data_clean(self.pwd_buffer)

        if self.curr_data is None:
            messagebox.showerror("---", "неверный пароль")
            self.root.destroy()
            return
        
        self.load_config()

        self.setup_ui()
        self.root.deiconify()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.mainloop()

    def on_close(self):
        if self.vault:
            self.vault.cleanup()
        self.root.destroy()
        
    def load_config(self):
        # инициализация настроек генератора
        try:
            if os.path.exists(GEN_FILE):
                with open(GEN_FILE, "r") as f:
                    settings = f.read()
                settings = settings.split()
                self.generator_len = int(settings[0])
                self.generator_chars = settings[1]
            else:
                self.generator_len = 17
                self.generator_chars = "all"
        except:
            print(f"файл настроек битый")
            self.generator_len = 17
            self.generator_chars = "all"

    def load_db(self):
        if not os.path.exists(DB_FILE):
            return {}
        
        try:
            with open(DB_FILE, "rb") as f:
                content = f.read()

            if len(content) < 32:
                return {}
            content = content[32:]

            #загрузка и шифрование паролей
            ram_data = {}
            for site, creds in self.vault.decrypt_data(content).items():
                pwd_enc = self.vault.encrypt_bytes(f"{site}|{creds['password']}".encode('utf-8'))
                ram_data[site] = {
                    "email": creds['email'],
                    "password": pwd_enc
                }

            return ram_data
        except Exception as e:
            print(f"error: {e}")
            return None

    def save_db(self):
        try:
            #выгрузка и расшифровка паролей
            data = {}
            for site, creds in self.curr_data.items():
                data[site] = {
                    "email": creds['email'],
                    "password": self.vault.decrypt_bytes(creds['password']).split("|", 1)[1]
                }
            
            enc_bytes = self.vault.encrypt_data(data)
            with open(DB_FILE, "wb") as f:
                f.write(self.vault.salt + enc_bytes)
            return True
        except Exception as e:
            messagebox.showerror("error", str(e))
            return False

    # UI handlers

    def generator(self):
        if self.generator_chars == "all":
            alph = string.ascii_letters + string.digits + string.punctuation
        elif self.generator_chars == "punc":
            alph = string.ascii_letters + string.punctuation
        elif self.generator_chars == "digs":
            alph = string.ascii_letters + string.digits
        elif self.generator_chars == "let":
            alph = string.ascii_letters
    
        pwd = ''.join(secrets.choice(alph) for _ in range(self.generator_len))
        
        self.pwd_entry.set_text(pwd)
        pyperclip.copy(pwd)
        messagebox.showinfo("---", "пароль скопирован")

    def save_entry(self):
        web = self.web_entry.get()
        email = self.email_entry.get()
        pwd = self.pwd_entry.get_bytes()

        if len(web) == 0 or len(pwd) == 0:
            messagebox.showwarning("---", "впишите сайт и пароль.")
            return
        
        pwd_enc = self.vault.encrypt_bytes(web.encode("utf-8") + b"|" + pwd)
        data_clean(pwd)
        self.pwd_entry.clear()

        self.curr_data[web] = {
            "email": email,
            "password": pwd_enc
        }

        if self.save_db():
            self.web_entry.delete(0, tk.END)
            self.pwd_entry.delete(0, tk.END)
            messagebox.showinfo("---", f"пароль сохранен")

    def find_pwd(self):
        web = self.web_entry.get()
        if web in self.curr_data:
            email = self.curr_data[web]["email"]
            pwd_enc = self.curr_data[web]["password"]
            
            try:
                pwd = self.vault.decrypt_bytes(pwd_enc).split("|", 1)[1]
                pyperclip.copy(pwd)
                messagebox.showinfo(web, f"email: {email}\nпароль: {pwd}\n\nпароль скопирован в буфер обмена")
            finally:
                #чистим переменные
                if "pwd" in locals():
                    data_clean(pwd)
                gc.collect()
        else:
            messagebox.showerror("---", f"данных не найдено")

    def save_config(self):
        if self.generator_chars_sel.get() == "буквы + цифры":
            self.gen_chars = "digs"
        elif self.generator_chars_sel.get() == "буквы + пунктуация":
            self.gen_chars = "punc"
        elif self.generator_chars_sel.get() == "буквы + цифры + пунктуация":
            self.gen_chars = "all"

        with open(GEN_FILE, "w") as f:
            f.write(f"{self.generator_len_sel.get()} {self.gen_chars}")

    def password_generator_config(self):
        conf_window = tk.Toplevel(self.root)
        conf_window.config(padx=50, pady=50)
        conf_window.title("конфиг генератора")
        self.generator_chars_sel = tk.StringVar()
        self.generator_len_sel = 17

        tk.Label(conf_window, text="выбор символов:").grid(column=0, row=0)
        tk.Label(conf_window, text="выбор длины пароля:").grid(column=0, row=1)

        choices = ["буквы + цифры", "буквы + пунктуация", "буквы + цифры + пунктуация"]
        ttk.Combobox(conf_window, width=36, textvariable=self.generator_chars_sel, values=choices).grid(column=1, row=0, padx=5)

        self.generator_len_sel = tk.Entry(conf_window, width=36)
        self.generator_len_sel.grid(column=1, row=1)
        self.generator_len_sel.insert(0, "17")
        self.generator_len_sel.focus()

        tk.Button(conf_window, text="сохранить конфиг", command=self.save_config).grid(column=0, columnspan=2, row=2, pady=10, padx=5, sticky="EW")


    def db_delete(self):
        ans = messagebox.askyesno("", "Это действие не обратимо, вы уверены?")
        if not ans:
            return
        os.remove(DB_FILE)
        self.curr_data = {}
    def change_db_pwd(self):
        print(1)

    def setup_ui(self):
        self.root.title("менеджер паролей")
        self.root.config(padx=50, pady=50)

        tk.Label(text="веб-сайт:").grid(column=0, row=1)
        tk.Label(text="email/логин:").grid(column=0, row=2)
        tk.Label(text="пароль:").grid(column=0, row=3)

        self.web_entry = tk.Entry(width=35)
        self.web_entry.grid(column=1, row=1)
        self.web_entry.focus()

        self.email_entry = tk.Entry(width=35)
        self.email_entry.grid(column=1, row=2, columnspan=2, sticky="EW")
        self.email_entry.insert(0, "aboba@example.com")

        self.pwd_entry = SecureEntry(self.root, mask_input=False, width=21) 
        self.pwd_entry.grid(column=1, row=3, sticky="EW")

        tk.Button(text="найти", command=self.find_pwd).grid(column=2, row=1, sticky="EW")
        tk.Button(text="сгенерировать", command=self.generator).grid(column=2, row=3, sticky="EW")
        tk.Button(text="добавить", width=36, command=self.save_entry).grid(column=1, row=4, columnspan=2, sticky="EW")

        tk.Button(text="настроить генератор пароля", width=18, command=self.password_generator_config).grid(column=1, row=5, padx=5, pady=10, columnspan=1, sticky="EW")
        tk.Button(text="удалить базу", command=self.db_delete).grid(column=0, row=5, padx=5, pady=10, sticky="EW")
        tk.Button(text="изменить пароль базы", command=self.change_db_pwd).grid(column=2, row=5, padx=5, pady=10, sticky="EW")

if __name__ == "__main__":
    app = passwword_manager_app()