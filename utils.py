import ctypes
import gc
import os
import subprocess

try:
    libc = ctypes.CDLL("libc.so.6")
except OSError:
    try:
        libc = ctypes.CDLL("libc.so")
    except OSError:
        raise OSError("libc не найдена")

# ssize_t read(int fd, void *buf, size_t count)
libc.read.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t]
libc.read.restype = ctypes.c_ssize_t

# int mlockall(int flags)
libc.mlockall.argtypes = [ctypes.c_int]
libc.mlockall.restype = ctypes.c_int

RECORD_SEP = bytearray(b'\x1E') 
FIELD_SEP = bytearray(b'\x1F')

#ram cleaner
def data_clean(data):
    if isinstance(data, bytearray):
        # (c_char * len) указатель на bytearray
        buffer = (ctypes.c_char * len(data)).from_buffer(data)
        # Зануляем буфер
        ctypes.memset(buffer, 0, len(data))
    del data
    gc.collect()

#защита от выгрузки в swap
def lock_memory():
    try:
        MCL_CURRENT = 1
        MCL_FUTURE = 2
        libc = ctypes.CDLL("libc.so.6")
        result = libc.mlockall(MCL_CURRENT | MCL_FUTURE)
        if result != 0:
            raise OSError("mlockall failed")
    except Exception as e:
        print(f"{e}")

#защищенный ввод секрета с помощью PinEntry
def get_master_password(
    title: str = "Безопасное хранилище паролей", 
    desc: str = "Введите мастер-пароль для доступа к хранилищу", 
    prompt: str = "Пороли:"):

    try:
        process = subprocess.Popen(
            ['pinentry'],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0 
        )
    except FileNotFoundError:
        raise RuntimeError("pinentry не установлен")

    fd_out = process.stdout.fileno()
    
    password = bytearray()
    # временный буфер
    line_buf = bytearray()
    
    c_byte = (ctypes.c_ubyte * 1)()

    def _read_byte_to_line():
        res = libc.read(fd_out, c_byte, 1)
        if res <= 0:
            return True # EOF
        
        val = c_byte[0] 
        if val == 10: # \n
            return True
        line_buf.append(val)
        return False

    def _wait_for_ok():
        while True:
            for i in range(len(line_buf)): line_buf[i] = 0
            line_buf.clear()
            
            while not _read_byte_to_line():
                pass
            
            if line_buf.startswith(b"OK"):
                return True
            if line_buf.startswith(b"ERR"):
                return False

    try:
        if not _wait_for_ok():
            raise Exception("ошибка инициализации Pinentry")

        cmds = [
            f"SETTITLE {title}\n".encode(),
            f"SETDESC {desc}\n".encode(),
            f"SETPROMPT {prompt}\n".encode(),
            b"GETPIN\n"
        ]

        for cmd in cmds:
            process.stdin.write(cmd)
            process.stdin.flush()
            
            while True:
                # jчистка буфера строки
                for i in range(len(line_buf)): line_buf[i] = 0
                line_buf.clear()
                
                eof = False
                while not eof:
                    eof = _read_byte_to_line()

                if line_buf.startswith(b"OK"):
                    break 
                
                elif line_buf.startswith(b"D "):
                    # пропуск "D " и игнорир \r
                    for i in range(2, len(line_buf)):
                        b = line_buf[i]
                        if b != 13: # не \r
                            password.append(b)
                
                elif line_buf.startswith(b"ERR"):
                    if b"canceled" in line_buf:
                        data_clean(password)
                        return bytearray()
                    else:
                        raise Exception(f"ошика Pinentry: {line_buf}")

    finally:
        data_clean(line_buf)
        c_byte[0] = 0
        
        try:
            process.stdin.write(b"BYE\n")
            process.stdin.close()
            process.stdout.close()
        except:
            pass
        process.terminate()
        process.wait()

    return password
    
def serialize_db(data_dict): # site[1F]Email[1F]Password[1E]Site2[1F]Email2[1F]Password2[1E]...
    buffer = bytearray()
    
    for site, creds in data_dict.items():
        site_b = bytearray(site.encode('utf-8'))
        email_b = bytearray(creds['email'].encode('utf-8'))
        pwd_b = creds['password']
        
        buffer.extend(site_b)
        buffer.extend(FIELD_SEP)
        buffer.extend(email_b)
        buffer.extend(FIELD_SEP)
        buffer.extend(pwd_b)
        buffer.extend(RECORD_SEP)
        
        data_clean(site_b)
        data_clean(email_b)
        
    return buffer

def deserialize_db(buffer):
    result = {}
    
    records = buffer.split(RECORD_SEP)
    
    for record in records:
        if not record:
            continue
            
        fields = record.split(FIELD_SEP)
        if len(fields) != 3:
            continue
            
        site_b, email_b, pwd_b = fields
        
        site_str = site_b.decode('utf-8')
        email_str = email_b.decode('utf-8')
        
        result[site_str] = {
            "email": email_str,
            "password": pwd_b
        }
        
        data_clean(site_b)
        data_clean(email_b)
        data_clean(record)
        
    return result