import ctypes
import os

try:
    _lib = ctypes.CDLL("libkeyutils.so.1")
except OSError:
    try:
        _lib = ctypes.CDLL("libkeyutils.so")
    except OSError:
        raise OSError("libkeyutils not found")

key_serial_t = ctypes.c_int32

KEY_SPEC_THREAD_KEYRING = -1
KEY_SPEC_PROCESS_KEYRING = -2
KEY_SPEC_SESSION_KEYRING = -3
KEY_SPEC_USER_KEYRING = -4
KEY_SPEC_USER_SESSION_KEYRING = -5


_lib.add_key.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, key_serial_t]
_lib.add_key.restype = key_serial_t

_lib.request_key.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, key_serial_t]
_lib.request_key.restype = key_serial_t

_lib.keyctl_read.argtypes = [key_serial_t, ctypes.c_char_p, ctypes.c_size_t]
_lib.keyctl_read.restype = ctypes.c_long

_lib.keyctl_revoke.argtypes = [key_serial_t]
_lib.keyctl_revoke.restype = ctypes.c_long

class KeyringManager:
    @staticmethod
    def add(description: str, payload: bytes, keyring=KEY_SPEC_SESSION_KEYRING) -> int:
        desc_b = description.encode('utf-8')
        if isinstance(payload, bytearray):
            c_payload = (ctypes.c_char * len(payload)).from_buffer(payload)
        else:
            c_payload = payload
        key_id = _lib.add_key(b"user", desc_b, c_payload, len(payload), keyring)
        if key_id == -1:
            err = ctypes.get_errno()
            raise OSError(err, os.strerror(err))
        return key_id

    @staticmethod
    def read(key_id: int) -> bytearray:
        size = _lib.keyctl_read(key_id, None, 0)
        if size == -1:
            return bytearray()
        
        buffer = ctypes.create_string_buffer(size)
        ret = _lib.keyctl_read(key_id, buffer, size)
        if ret == -1:
            return bytearray()
        try:
            return bytearray(buffer.raw[:ret])
        finally:
            ctypes.memset(buffer, 0, size)

    @staticmethod
    def revoke(key_id: int): 
        _lib.keyctl_revoke(key_id)
