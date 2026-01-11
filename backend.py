import json
import os
import hmac
from linux_keyring import KeyringManager, KEY_SPEC_PROCESS_KEYRING

from gostcrypto import gostcipher, gosthmac, gostpbkdf, gosthash

from utils import data_clean

# backend logic
class gost_vault:
    def __init__(self, paster_pwd, salt=None):
        if salt is None:
            self.salt = os.urandom(32)
        else:
            self.salt = salt

        # PBKDF
        pbkdf_obj = gostpbkdf.new(password=paster_pwd, salt=self.salt, counter=10**3)
        key_mats = bytearray(pbkdf_obj.derive(64))

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
    #PKCS7
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
    
    #генерация iv для шифрования паролей
    def _generate_iv_simple(self, init_data):
        if isinstance(init_data, str):
            data = init_data.encode('utf-8')
        else:
            data = init_data
        
        hasher = gosthash.new('stribog256', data=data)
        digest = hasher.digest()
        return digest[:self.kuzn_size]

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
    def encrypt_bytes(self, data, init_data=None):
        self.key_enc = self._get_key_enc()
        try:
            if init_data is None:
                kuznechik = gostcipher.new('kuznechik', self.key_enc, gostcipher.MODE_ECB)
                return kuznechik.encrypt(self._pad(data))
            else:
                iv_d = self._generate_iv_simple(init_data=init_data)
                
                kuznechik = gostcipher.new('kuznechik', self.key_enc, gostcipher.MODE_CBC, iv=iv_d)
                return kuznechik.encrypt(self._pad(data))
        finally:
            data_clean(self.key_enc)

    #расшифровываем отдельные данные
    def decrypt_bytes(self, enc_bytes, init_data=None):
        self.key_enc = self._get_key_enc()
        try:
            if init_data is None:
                kuznechik = gostcipher.new('kuznechik', self.key_enc, gostcipher.MODE_ECB)
                return self._unpad(kuznechik.decrypt(enc_bytes)).decode("utf-8")
            else:
                iv_d = self._generate_iv_simple(init_data=init_data)
                
                kuznechik = gostcipher.new('kuznechik', self.key_enc, gostcipher.MODE_CBC, iv=iv_d)
                return self._unpad(kuznechik.decrypt(enc_bytes)).decode("utf-8")
        finally:
            data_clean(self.key_enc)
        
    def cleanup(self):
        try:
            KeyringManager.revoke(self.key_enc_id)
            KeyringManager.revoke(self.key_mac_id)
        except Exception as e:
            print(f"error: {e}")
            pass