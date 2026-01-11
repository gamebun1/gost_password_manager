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
    def __init__(self, parent, mask_input=True, max_len=64, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        
        self.MAX_LEN = max_len
        self.mask_input = mask_input
        
        self._buffer = bytearray(self.MAX_LEN)
        self._data_len = 0 
        
        self._char_sizes = [] 

        self.bind('<Key>', self.on_key_press)
        
        self.bind('<Control-c>', lambda e: "break")
        self.bind('<Control-x>', lambda e: "break")
        self.bind('<<Copy>>', lambda e: "break")
        self.bind('<<Cut>>', lambda e: "break")
        
        self.bind('<<Paste>>', self.handle_paste)
        self.bind('<Control-v>', self.handle_paste)
        
        self.bind('<Button-3>', lambda e: "break")

    def get_cursor_position(self):
        return self.index(tk.INSERT)

    def _wipe_tail(self):
        if self._data_len < self.MAX_LEN:
            offset = self._data_len
            length = self.MAX_LEN - self._data_len
            # получаем указатель на начало хвоста
            ptr = (ctypes.c_char * length).from_buffer(self._buffer, offset)
            ctypes.memset(ptr, 0, length)

    def _shift_buffer_right(self, byte_idx, shift_amount):
        if self._data_len + shift_amount > self.MAX_LEN:
            return False # переполнение
        
        count = self._data_len - byte_idx
        if count > 0:
            src_addr = (ctypes.c_char * count).from_buffer(self._buffer, byte_idx)
            dst_addr = (ctypes.c_char * count).from_buffer(self._buffer, byte_idx + shift_amount)
            ctypes.memmove(dst_addr, src_addr, count)
            
        return True

    def _shift_buffer_left(self, byte_idx, shift_amount):
        count = self._data_len - (byte_idx + shift_amount)
        if count > 0:
            src_addr = (ctypes.c_char * count).from_buffer(self._buffer, byte_idx + shift_amount)
            dst_addr = (ctypes.c_char * count).from_buffer(self._buffer, byte_idx)
            ctypes.memmove(dst_addr, src_addr, count)
        
        self._data_len -= shift_amount
        self._wipe_tail()

    def _get_byte_offset(self, char_index):
        return sum(self._char_sizes[:char_index])


    def _insert_text_at_cursor(self, text):
        if not text: return
        
        total_new_bytes = sum(len(c.encode('utf-8')) for c in text)
        if self._data_len + total_new_bytes > self.MAX_LEN:
            return

        char_pos = self.get_cursor_position()
        
        if self.selection_present():
            self._delete_selection()
            char_pos = self.get_cursor_position()

        byte_pos = self._get_byte_offset(char_pos)

        if not self._shift_buffer_right(byte_pos, total_new_bytes):
            return

        current_byte_pos = byte_pos
        for char in text:
            char_bytes = char.encode('utf-8')
            b_len = len(char_bytes)
            
            for i, b in enumerate(char_bytes):
                self._buffer[current_byte_pos + i] = b
            
            self._char_sizes.insert(char_pos, b_len)
            char_pos += 1
            current_byte_pos += b_len

        self._data_len += total_new_bytes
        
        display_text = "*" * len(text) if self.mask_input else text
        self.insert(tk.INSERT, display_text)
        
        del text
        gc.collect()

    def _delete_selection(self):
        try:
            start_char = self.index(tk.SEL_FIRST)
            end_char = self.index(tk.SEL_LAST)
            
            start_byte = self._get_byte_offset(start_char)

            bytes_to_del = sum(self._char_sizes[start_char:end_char])
            
            self._shift_buffer_left(start_byte, bytes_to_del)
            
            del self._char_sizes[start_char:end_char]
            
            self.delete(start_char, end_char)
        except tk.TclError:
            pass

    def _backspace(self):
        if self.selection_present():
            self._delete_selection()
            return
            
        pos = self.get_cursor_position()
        if pos > 0:
            # удаляем 1 символ слева от курсора
            char_len = self._char_sizes[pos-1]
            byte_start = self._get_byte_offset(pos-1)
            
            self._shift_buffer_left(byte_start, char_len)
            del self._char_sizes[pos-1]
            self.delete(pos-1)

    def _delete_key(self):
        if self.selection_present():
            self._delete_selection()
            return

        pos = self.get_cursor_position()
        if pos < len(self._char_sizes):
            # удаляем 1 символ справа от курсора
            char_len = self._char_sizes[pos]
            byte_start = self._get_byte_offset(pos)
            
            self._shift_buffer_left(byte_start, char_len)
            del self._char_sizes[pos]
            self.delete(pos)

    def handle_paste(self, event):
        try:
            text = self.clipboard_get()
            if text:
                self._insert_text_at_cursor(text)
        except tk.TclError:
            pass
        return "break"

    def on_key_press(self, event):
        key = event.keysym
        
        if key in ('Left', 'Right', 'Up', 'Down', 'Home', 'End', 
                   'Shift_L', 'Shift_R', 'Control_L', 'Control_R', 
                   'Alt_L', 'Alt_R', 'Caps_Lock', 'Num_Lock', 
                   'Return', 'Tab', 'Escape'):
            return None 

        if key == 'BackSpace':
            self._backspace()
            return "break"

        if key == 'Delete':
            self._delete_key()
            return "break"

        # ввод символов
        if len(event.char) > 0 and ord(event.char) >= 32:
            self._insert_text_at_cursor(event.char)
            del event
            gc.collect()
            return "break"

        return "break" 

    def get_bytes(self):
        return self._buffer[:self._data_len]

    def clear(self):
        # жесткая очистка памяти
        ptr = (ctypes.c_char * self.MAX_LEN).from_buffer(self._buffer)
        ctypes.memset(ptr, 0, self.MAX_LEN)
        
        self._data_len = 0
        self._char_sizes = []
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
                pwd_enc = self.vault.encrypt_bytes(f"{site}|{creds['password']}".encode('utf-8'), init_data=site)
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
                    "password": self.vault.decrypt_bytes(creds['password'], init_data=site).split("|", 1)[1]
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
        
        pwd_enc = self.vault.encrypt_bytes(web.encode("utf-8") + b"|" + pwd, init_data=web)
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
                pwd = self.vault.decrypt_bytes(pwd_enc, init_data=web).split("|", 1)[1]
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
