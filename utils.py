import ctypes
import gc

#ram cleaner
def data_clean(data):
    if isinstance(data, bytearray):
        # (c_char * len)
        buffer = (ctypes.c_char * len(data)).from_buffer(data)
        # Зануляем буфер
        ctypes.memset(buffer, 0, len(data))
    del data
    gc.collect()