import os
import time
import base64
import json

import psutil
import win32api
import subprocess

import pyperclip
import pyautogui

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.ciphers.modes import GCM
from cryptography.hazmat.backends import default_backend

SETTINGS : dict = {}
KEY_FILE_NAME = "crypt_key.key"
METADATA_FILE_SUFFIX = ".metadata.json"
GCM_IV_SIZE = 12
GCM_TAG_SIZE = 16


def load_settings():
    global SETTINGS
    settings_file = os.path.join(os.path.dirname(__file__), "settings.json")
    if os.path.exists(settings_file):
        with open(settings_file, 'r') as file:
            SETTINGS = json.load(file)

def write_metadata(file_path, attribute_name, value):
    metadata_file = f"{file_path}{METADATA_FILE_SUFFIX}"
    metadata = {}

    if os.path.exists(metadata_file):
        try:
            with open(metadata_file, 'r', encoding='utf-8') as file:
                metadata = json.load(file)
        except (json.JSONDecodeError, OSError):
            metadata = {}

    metadata[attribute_name] = value

    with open(metadata_file, 'w', encoding='utf-8') as file:
        json.dump(metadata, file, indent=4)


def read_metadata(file_path, attribute_name):
    metadata_file = f"{file_path}{METADATA_FILE_SUFFIX}"
    if not os.path.exists(metadata_file):
        return None

    try:
        with open(metadata_file, 'r', encoding='utf-8') as file:
            metadata = json.load(file)
            return metadata.get(attribute_name, None)
    except (json.JSONDecodeError, OSError):
        return None


def get_key_file_path() -> str:
    return os.path.join(os.path.dirname(__file__), KEY_FILE_NAME)


def create_new_crypt_key() -> bytes:
    crypt_key = os.urandom(32)  # AES-256 requires a 32-byte key
    key_file = get_key_file_path()
    with open(key_file, 'wb') as file:
        file.write(crypt_key)
    return crypt_key

def get_crypt_key_from_file() -> bytes:
    key_file = get_key_file_path()
    if not os.path.exists(key_file):
        raise FileNotFoundError("Cryptographic key file not found.")
    with open(key_file, 'rb') as file:
        crypt_key = file.read()
    if len(crypt_key) != 32:
        raise ValueError("Invalid cryptographic key length.")
    return crypt_key


def _looks_like_encrypted_payload(data: str) -> bool:
    try:
        encrypted_data = base64.b64decode(data.encode('utf-8'))
    except Exception:
        return False
    return len(encrypted_data) >= GCM_IV_SIZE + GCM_TAG_SIZE + 1


def _decrypt_payload(data : str, crypt_key : bytes) -> str:
    encrypted_data = base64.b64decode(data.encode('utf-8'))
    if len(encrypted_data) < GCM_IV_SIZE + GCM_TAG_SIZE + 1:
        raise ValueError("Encrypted payload is too short.")

    iv = encrypted_data[:GCM_IV_SIZE]
    tag = encrypted_data[GCM_IV_SIZE:GCM_IV_SIZE + GCM_TAG_SIZE]
    ciphertext = encrypted_data[GCM_IV_SIZE + GCM_TAG_SIZE:]

    cipher = Cipher(algorithms.AES(crypt_key), GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode('utf-8')


def _encrypt_payload(plaintext : bytes, crypt_key : bytes) -> str:
    iv = os.urandom(GCM_IV_SIZE)
    cipher = Cipher(algorithms.AES(crypt_key), GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return base64.b64encode(iv + encryptor.tag + ciphertext).decode('utf-8')


def encrypt_data(data : str, path : str) -> str:
    plaintext = data.encode('utf-8')
    crypt_key = create_new_crypt_key()
    encrypted_data = _encrypt_payload(plaintext, crypt_key)

    if read_metadata(path, "Encrypted") is None:
        write_metadata(path, "Encrypted", "yes")

    return encrypted_data


def decrypt_data(data : str, path : str) -> str:
    metadata = read_metadata(path, "Encrypted")
    if metadata is None:
        if os.path.exists(get_key_file_path()) and _looks_like_encrypted_payload(data):
            try:
                decrypted = _decrypt_payload(data, get_crypt_key_from_file())
                write_metadata(path, "Encrypted", "yes")
                return decrypted
            except Exception:
                return data
        return data

    if metadata == "yes":
        return _decrypt_payload(data, get_crypt_key_from_file())

    return data

def unlock_enpass(path : str) -> None:
    print(f"Unlocking Enpass with Secure Stick")
    file_path : str = os.path.join(path, "enpass-key.enpass")
    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            master_password : str = file.read()
        
        master_password = decrypt_data(master_password, file_path)
        
        pyperclip.copy(master_password)
        
        enpass_uri = "enpass://"
        subprocess.run(["start", enpass_uri], shell=True, check=True)
        
        time.sleep(1)
        pyautogui.hotkey('ctrl', 'v')
        pyautogui.press('enter')
        
        time.sleep(1)
        pyperclip.copy("")
        
        encrypted_master_password = encrypt_data(master_password, file_path)
        
        with open(file_path, 'w') as file:
            file.write(encrypted_master_password)
     
def get_usb_devices() -> list:
    usb_devices : list = []
    partitions = psutil.disk_partitions()
    
    for partition in partitions:
        try:
            if 'removable' in partition.opts or (os.name == 'nt' and 'cdrom' not in partition.opts):
                device_info = {}
                device_info['path'] = partition.device
                device_info['volume_name'] = win32api.GetVolumeInformation(partition.device)[0]
                
                usb_devices.append(device_info)
        except Exception as e:
            continue

    return usb_devices  
   
def scan_for_unlock_device() -> None:
    end_scan : bool = False
    
    while not end_scan:
        devices = get_usb_devices()
        for device in devices:
            if device['volume_name'] == SETTINGS["SECURE_USB_DEVICE_NAME"]:
                end_scan = True
                unlock_enpass(device['path'])
                break

        time.sleep(1)

if __name__ == "__main__":
    load_settings()
    scan_for_unlock_device()