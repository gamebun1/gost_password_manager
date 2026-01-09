import os
import secrets
import string
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import pyperclip
from backend import gost_vault
from utils import data_clean
import ctypes
import gc

DB_FILE = "passwords"
GEN_FILE = "generator"

#secure tk entry
class SecureEntry(tk.Entry):
    def __init__(self, parent, mask_input=True, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.pwd_buffer = bytearray()
        self.mask_input = mask_input
        
        self.bind('<Key>', self.on_key_press)
        
        # блокируем стандартные механизмы копирования
        self.bind('<Control-c>', lambda e: "break")
        self.bind('<Control-x>', lambda e: "break")
        self.bind('<<Copy>>', lambda e: "break")
        self.bind('<<Cut>>', lambda e: "break")
        
        # перехват вставки
        self.bind('<<Paste>>', self.handle_paste)
        self.bind('<Control-v>', self.handle_paste)
        
        # отключаем мышь для копирования
        self.bind('<Button-3>', lambda e: "break") 

    def get_cursor_position(self):
        return self.index(tk.INSERT)

    def handle_paste(self, event):
        try:
            text = self.clipboard_get()
            if not text:
                return "break"
            
            self._insert_text_at_cursor(text)
        except tk.TclError:
            pass
        return "break"

    def _insert_text_at_cursor(self, text):
        pos = self.get_cursor_position()
        
        # обработка выделения текста
        if self.selection_present():
            self._delete_selection()
            pos = self.get_cursor_position()

        # вставляем данные в защищенный буфер
        text_bytes = text.encode('utf-8')
        self.pwd_buffer[pos:pos] = text_bytes
        
        # вставляем данные в GUI
        display_text = "*" * len(text) if self.mask_input else text
        self.insert(pos, display_text)

    def _delete_selection(self):
        try:
            start = self.index(tk.SEL_FIRST)
            end = self.index(tk.SEL_LAST)
            del self.pwd_buffer[start:end]
            self.delete(start, end)
        except tk.TclError:
            pass

    def on_key_press(self, event):
        key = event.keysym
        
        # игнорируем нажатия
        if key in ('Shift_L', 'Shift_R', 'Control_L', 'Control_R', 'Alt_L', 'Alt_R', 'Caps_Lock', 'Num_Lock'):
            return None

        if key in ('Left', 'Right', 'Up', 'Down', 'Home', 'End'):
            return None

        if key == 'BackSpace':
            if self.selection_present():
                self._delete_selection()
            else:
                pos = self.get_cursor_position()
                if pos > 0:
                    del self.pwd_buffer[pos-1]
                    self.delete(pos-1)
            return "break"

        if key == 'Delete':
            if self.selection_present():
                self._delete_selection()
            else:
                pos = self.get_cursor_position()
                if pos < len(self.pwd_buffer):
                    del self.pwd_buffer[pos]
                    self.delete(pos)
            return "break"

        if key in ('Return', 'Tab'):
            return None

        if len(event.char) > 0 and ord(event.char) >= 32:
            self._insert_text_at_cursor(event.char)
            return "break" #

        return None

    def get_bytes(self):
        return self.pwd_buffer

    def clear(self):
        if self.pwd_buffer:
            # зануление данных
            buf_len = len(self.pwd_buffer)
            if buf_len > 0:
                buffer = (ctypes.c_char * buf_len).from_buffer(self.pwd_buffer)
                ctypes.memset(buffer, 0, buf_len)
            del self.pwd_buffer
            self.pwd_buffer = bytearray()
        self.delete(0, tk.END)

    def set_text(self, text):
        self.clear()
        self._insert_text_at_cursor(text)

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
        data_clean(self.curr_data)
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
        tk.Button(text="удалить базу", command=self.db_delete).grid(column=2, row=5, padx=5, pady=10, sticky="EW")
        #tk.Button(text="изменить пароль базы", command=self.change_db_pwd).grid(column=2, row=5, padx=5, pady=10, sticky="EW")
