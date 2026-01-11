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