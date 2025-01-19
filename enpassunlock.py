import os
import time
import base64
import json

import psutil
import win32api
import subprocess

import pyperclip
import pyautogui

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Volume Name of the External Device that contains the Enpass maaster password
SECURE_USB_DEVICE_NAME : str = "THEDATAS"

def write_metadata(file_path, attribute_name, value):
    metadata_file = f"{file_path}.metadata.json"
    metadata = {}
    
    if os.path.exists(metadata_file):
        with open(metadata_file, 'r') as file:
            metadata = json.load(file)
    
    metadata[attribute_name] = value
    
    with open(metadata_file, 'w') as file:
        json.dump(metadata, file, indent=4)
    print(f"Attribute '{attribute_name}' written to {metadata_file}.")

def read_metadata(file_path, attribute_name):
    metadata_file = f"{file_path}.metadata.json"
    try:
        with open(metadata_file, 'r') as file:
            metadata = json.load(file)
            return metadata.get(attribute_name, None)
    except FileNotFoundError:
        print(f"No metadata file found for {file_path}.")
        return None

def create_new_crypt_key() -> bytes:
    crypt_key = os.urandom(32)  # AES-256 requires a 32-byte key
    key_file = os.path.join(os.path.dirname(__file__), "crypt_key.key")
    with open(key_file, 'wb') as file:
        file.write(crypt_key)
    return crypt_key

def get_crypt_key_from_file() -> bytes:
    key_file = os.path.join(os.path.dirname(__file__), "crypt_key.key")
    if not os.path.exists(key_file):
        raise FileNotFoundError("Cryptographic key file not found.")
    with open(key_file, 'rb') as file:
        return file.read()

def encrypt_data(data: str, path: str) -> str:
    # Convert plaintext to bytes
    plaintext = data.encode('utf-8')

    # Generate or load cryptographic key
    crypt_key = create_new_crypt_key()

    # Generate a random 16-byte IV (Initialization Vector)
    iv = os.urandom(16)

    # AES encryption
    cipher = Cipher(algorithms.AES(crypt_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Combine IV and ciphertext for storage
    encrypted_data = base64.b64encode(iv + ciphertext).decode('utf-8')
    
    if read_metadata(path, "Encrypted") is None:
        write_metadata(path, "Encrypted", "yes")
    
    return encrypted_data

def decrypt_data(data: str, path: str) -> str:
    if read_metadata(path, "Encrypted") is None:
        return data

    # Load cryptographic key
    crypt_key = get_crypt_key_from_file()

    # Decode the base64-encoded data to get IV + ciphertext
    encrypted_data = base64.b64decode(data.encode('utf-8'))
    iv = encrypted_data[:16]  # Extract the first 16 bytes as the IV
    ciphertext = encrypted_data[16:]  # The rest is the ciphertext

    # AES decryption
    cipher = Cipher(algorithms.AES(crypt_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext.decode('utf-8')

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
            if device['volume_name'] == SECURE_USB_DEVICE_NAME:
                end_scan = True
                unlock_enpass(device['path'])
                break

        time.sleep(1)

if __name__ == "__main__":
    scan_for_unlock_device()