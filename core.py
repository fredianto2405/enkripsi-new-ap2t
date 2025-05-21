import socket
import psutil
import platform
import getpass
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode

key = b'ThisIsMySecretKey123456789012312'
iv = b'My16ByteInitVect'

def encrypt(key, iv, plaintext):
  padder = padding.PKCS7(128).padder()
  padded_data = padder.update(plaintext.encode()) + padder.finalize()
  cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
  encryptor = cipher.encryptor()
  ciphertext = encryptor.update(padded_data) + encryptor.finalize()
  return b64encode(ciphertext).decode()

def decrypt(key, iv, ciphertext):
  ciphertext = b64decode(ciphertext)
  cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
  decryptor = cipher.decryptor()
  decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
  unpadder = padding.PKCS7(128).unpadder()
  plaintext_bytes = unpadder.update(decrypted_padded) + unpadder.finalize()
  return plaintext_bytes.decode()

def get_wifi_mac():
  for interface_name, addresses in psutil.net_if_addrs().items():
    if "wlan" in interface_name.lower() or "wi-fi" in interface_name.lower():
      for addr in addresses:
        if addr.family == psutil.AF_LINK:
          return interface_name, addr.address
  return None, None

hostname = socket.gethostname()
ip_address = socket.gethostbyname(hostname)

os_info = {
  "os_name": platform.system(),
  "release": platform.release(),
  "version": platform.version(),
  "platform": platform.platform(),
  "architecture": platform.machine()
}

iface, mac = get_wifi_mac()
mac_info = {
  "interface": iface,
  "mac_address": mac
}

data = {
  "ip_address": ip_address,
  "mac_info": mac_info,
  "hostname": hostname,
  "username": getpass.getuser(),
  "os_info": os_info
}

json_data = json.dumps(data)
print("JSON Data:", json_data)

ciphertext = encrypt(key, iv, json_data)
print("\nEncrypted:", ciphertext)

plaintext = decrypt(key, iv, ciphertext)
print("\nDecrypted:", plaintext)