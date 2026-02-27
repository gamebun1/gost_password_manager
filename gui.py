import os
import pwd
import secrets
import string
import customtkinter as ctk
import pyperclip
from backend import gost_vault
from utils import data_clean, get_master_password
import gc

DB_FILE = "passwords"
GEN_FILE = "generator"


ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

# красивск окно
class ModernMessageBox:
    def __init__(self, title, message, mode="info"):
        self.window = ctk.CTkToplevel()
        self.window.title(title)
        self.window.geometry("400x180")
        self.window.resizable(False, False)
        
        self.window.attributes("-topmost", True)
        self.result = False
        
        self.window.wait_visibility()
        self.window.grab_set()
        
        lbl = ctk.CTkLabel(self.window, text=message, font=("Arial", 14), wraplength=350)
        lbl.pack(pady=30, padx=20, expand=True)
        
        # фрейм для кнопок
        btn_frame = ctk.CTkFrame(self.window, fg_color="transparent")
        btn_frame.pack(pady=(0, 20))
        
        # разные кнопки 
        if mode == "askyesno":
            ctk.CTkButton(btn_frame, text="Да", width=100, fg_color="#C0392B", hover_color="#922B21", command=self.set_yes).pack(side="left", padx=10)
            ctk.CTkButton(btn_frame, text="Нет", width=100, command=self.set_no).pack(side="right", padx=10)
        elif mode == "error":
            ctk.CTkButton(btn_frame, text="OK", width=100, fg_color="#C0392B", hover_color="#922B21", command=self.set_no).pack()
        else:
            ctk.CTkButton(btn_frame, text="OK", width=100, command=self.set_no).pack()
            
        self.window.wait_window()
        
    def set_yes(self):
        self.result = True
        self.window.destroy()
        
    def set_no(self):
        self.result = False
        self.window.destroy()


class passwword_manager_app:
    def __init__(self):
        self.root = ctk.CTk()
        self.root.withdraw() 
        
        # Заглушка для PinEntry
        self.pwd_buffer = get_master_password()
        
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
            ModernMessageBox("Ошибка", str(e), "error")
            self.curr_data = None
        finally:
            data_clean(self.pwd_buffer)

        if self.curr_data is None:
            print("Неверный пароль или ошибка расшифровки базы")
            self.root.destroy()
            return
        
        self.load_config()

        self.setup_ui()
        self.root.deiconify()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.mainloop()

    def on_close(self):
        if hasattr(self, 'vault') and self.vault:
            self.vault.cleanup()
        self.root.destroy()
        
    def load_config(self):
        try:
            if os.path.exists(GEN_FILE):
                with open(GEN_FILE, "r") as f:
                    settings = f.read().split()
                self.generator_len = int(settings[0])
                self.generator_chars = settings[1]
            else:
                self.generator_len = 17
                self.generator_chars = "all"
        except Exception as e:
            print(f"Файл настроек битый: {e}")
            self.generator_len = 17
            self.generator_chars = "all"

    def load_db(self):
        if not os.path.exists(DB_FILE):
            return {}
        
        try:
            with open(DB_FILE, "rb") as f:
                content = bytearray(f.read())

            if len(content) < 32:
                data_clean(content)
                return {}
            content = content[32:]
            dec_content = self.vault.decrypt_data(content)
            data_clean(content)

            if dec_content is None:
                return None 

            ram_data = {}
            for site, creds in dec_content.items():
                pwd_enc = self.vault.encrypt_ram_pwd(site, creds['password'])
                ram_data[site] = {
                    "email": creds['email'],
                    "password": pwd_enc
                }

                data_clean(creds['password']) 

            return ram_data
        except Exception as e:
            print(f"Ошибка загрузки БД: {e}")
            return None

    def save_db(self):
        try:
            data = {}
            for site, creds in self.curr_data.items():
                data[site] = {
                    "email": creds['email'],
                    "password": self.vault.decrypt_ram_pwd(creds['password'], site)
                }
            
            enc_bytes = self.vault.encrypt_data(data)

            for site, creds in data.items():
                data_clean(creds['password'])
            data.clear()

            with open(DB_FILE, "wb") as f:
                f.write(bytes(self.vault.salt))
                f.write(bytes(enc_bytes))

            if isinstance(enc_bytes, bytearray):
                data_clean(enc_bytes)

            return True
        except Exception as e:

            import traceback
            traceback.print_exc()

            ModernMessageBox("Ошибка", repr(e), "error")
            return False

    def generator(self):
        if self.generator_chars == "all":
            alph = string.ascii_letters + string.digits + string.punctuation
        elif self.generator_chars == "punc":
            alph = string.ascii_letters + string.punctuation
        elif self.generator_chars == "digs":
            alph = string.ascii_letters + string.digits
        elif self.generator_chars == "let":
            alph = string.ascii_letters
        else:
            alph = string.ascii_letters + string.digits + string.punctuation
    
        pwd = ''.join(secrets.choice(alph) for _ in range(self.generator_len))
        
        self.pwd_entry.delete(0, 'end')
        self.pwd_entry.insert(0, pwd)
        
        pyperclip.copy(pwd)
        ModernMessageBox("Успех", "Сгенерированный пароль скопирован в буфер обмена", "info")

    def save_entry(self):
        web = self.web_entry.get()
        email = self.email_entry.get()
        
        pwd_ba = bytearray(self.pwd_entry.get().encode("utf-8"))

        if len(web) == 0 or len(pwd_ba) == 0:
            ModernMessageBox("Внимание", "Впишите сайт и пароль", "warning")
            return
        

        pwd_enc = self.vault.encrypt_ram_pwd(web, pwd_ba)
        data_clean(pwd_ba)

        self.pwd_entry.delete(0, 'end')

        self.curr_data[web] = {
            "email": email,
            "password": pwd_enc
        }

        if self.save_db():
            self.web_entry.delete(0, 'end')
            self.pwd_entry.delete(0, 'end')
            ModernMessageBox("Успех", f"Пароль для {web} успешно сохранен", "info")

    def find_pwd(self):
        web = self.web_entry.get()
        if web in self.curr_data:
            email = self.curr_data[web]["email"]
            pwd_enc = self.curr_data[web]["password"]
            
            try:
                pwd_ba = self.vault.decrypt_ram_pwd(pwd_enc, web)
                pwd_str = pwd_ba.decode("utf-8")
                pyperclip.copy(pwd_str)

                data_clean(pwd_ba)

                ModernMessageBox(web, f"Email/Логин: {email}\nПароль: {pwd_str}\n\nПароль скопирован в буфер обмена", "info")
            finally:
                if "pwd_ba" in locals():
                    data_clean(pwd_ba)
                gc.collect()
        else:
            ModernMessageBox("Ошибка", f"Данных для сайта '{web}' не найдено", "error")

    def save_config(self, window=None):
        if self.generator_chars_sel.get() == "буквы + цифры":
            self.gen_chars = "digs"
        elif self.generator_chars_sel.get() == "буквы + пунктуация":
            self.gen_chars = "punc"
        elif self.generator_chars_sel.get() == "буквы + цифры + пунктуация":
            self.gen_chars = "all"
        else:
            self.gen_chars = "let"

        try:
            self.generator_len = int(self.generator_len_sel.get())
        except ValueError:
            ModernMessageBox("Ошибка", "Длина пароля должна быть числом", "error")
            return

        with open(GEN_FILE, "w") as f:
            f.write(f"{self.generator_len} {self.gen_chars}")
            
        if window:
            window.destroy()
            ModernMessageBox("Успех", "Конфигурация генератора сохранена", "info")

    def password_generator_config(self):
        conf_window = ctk.CTkToplevel(self.root)
        conf_window.geometry("450x200")
        conf_window.title("Конфигурация генератора")
        
        conf_window.wait_visibility() 
        conf_window.grab_set()
        conf_window.focus()

        ctk.CTkLabel(conf_window, text="Выбор символов:").grid(column=0, row=0, padx=20, pady=(20, 10), sticky="w")
        ctk.CTkLabel(conf_window, text="Длина пароля:").grid(column=0, row=1, padx=20, pady=10, sticky="w")

        self.generator_chars_sel = ctk.StringVar()
        choices =["буквы + цифры", "буквы + пунктуация", "буквы + цифры + пунктуация"]
        
        combo = ctk.CTkComboBox(conf_window, width=220, variable=self.generator_chars_sel, values=choices)
        combo.grid(column=1, row=0, padx=20, pady=(20, 10))
        
        if self.generator_chars == "digs":
            combo.set("буквы + цифры")
        elif self.generator_chars == "punc":
            combo.set("буквы + пунктуация")
        else:
            combo.set("буквы + цифры + пунктуация")

        self.generator_len_sel = ctk.CTkEntry(conf_window, width=220)
        self.generator_len_sel.grid(column=1, row=1, padx=20, pady=10)
        self.generator_len_sel.insert(0, str(self.generator_len))

        ctk.CTkButton(conf_window, text="Сохранить настройки", command=lambda: self.save_config(conf_window)).grid(column=0, columnspan=2, row=2, pady=20, padx=20, sticky="ew")

    def db_delete(self):
        ans = ModernMessageBox("Удаление базы", "Это действие необратимо! Вы уверены, что хотите удалить базу паролей?", "askyesno").result
        if not ans:
            return
        if os.path.exists(DB_FILE):
            os.remove(DB_FILE)
        data_clean(self.curr_data)
        self.curr_data = {}
        ModernMessageBox("Удалено", "База паролей успешно удалена.", "info")

    def setup_ui(self):
        self.root.title("Менеджер паролей")
        self.root.geometry("600x380")
        self.root.resizable(False, False)

        self.root.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(self.root, text="Веб-сайт:", font=("Arial", 14)).grid(column=0, row=1, padx=20, pady=(30, 10), sticky="e")
        ctk.CTkLabel(self.root, text="Email/Логин:", font=("Arial", 14)).grid(column=0, row=2, padx=20, pady=10, sticky="e")
        ctk.CTkLabel(self.root, text="Пароль:", font=("Arial", 14)).grid(column=0, row=3, padx=20, pady=10, sticky="e")

        self.web_entry = ctk.CTkEntry(self.root, height=35)
        self.web_entry.grid(column=1, row=1, padx=(0, 20), pady=(30, 10), sticky="ew")
        self.web_entry.focus()

        self.email_entry = ctk.CTkEntry(self.root, height=35)
        self.email_entry.grid(column=1, row=2, columnspan=2, padx=(0, 20), pady=10, sticky="ew")
        self.email_entry.insert(0, "aboba@example.com")

        self.pwd_entry = ctk.CTkEntry(self.root, height=35)
        self.pwd_entry.grid(column=1, row=3, padx=(0, 20), pady=10, sticky="ew")

        ctk.CTkButton(self.root, text="Найти", height=35, width=120, command=self.find_pwd).grid(column=2, row=1, padx=(0, 20), pady=(30, 10))
        ctk.CTkButton(self.root, text="Сгенерировать", height=35, width=120, command=self.generator).grid(column=2, row=3, padx=(0, 20), pady=10)
        
        ctk.CTkButton(self.root, text="Добавить / Обновить", height=35, command=self.save_entry).grid(column=1, row=4, columnspan=2, padx=(0, 20), pady=(10, 30), sticky="ew")

        bottom_frame = ctk.CTkFrame(self.root, fg_color="transparent")
        bottom_frame.grid(column=0, row=5, columnspan=3, padx=20, pady=10, sticky="ew")
        bottom_frame.grid_columnconfigure(0, weight=1)
        bottom_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkButton(bottom_frame, text="Настроить генератор пароля", fg_color="#454545", hover_color="#333333", command=self.password_generator_config).grid(column=0, row=0, padx=(0, 10), sticky="ew")
        ctk.CTkButton(bottom_frame, text="Удалить базу", fg_color="#C0392B", hover_color="#922B21", command=self.db_delete).grid(column=1, row=0, padx=(10, 0), sticky="ew")
