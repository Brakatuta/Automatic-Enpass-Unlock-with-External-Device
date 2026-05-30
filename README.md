# 🔐 EnpassUnlocker

A Windows utility that automatically unlocks [Enpass](https://www.enpass.io/) when you plug in a designated USB stick — no typing needed.

> ⚠️ **Important:** This tool is purely a convenience utility to speed up your login. It does **not** replace your master password. Always remember your Enpass master password — if your USB stick is lost, corrupted, or your system files are gone, it is the only way to regain access to your vault.

---

## How It Works

1. You plug in your designated USB stick
2. EnpassUnlocker detects it by its volume name
3. It reads the encrypted master password from the stick
4. It launches Enpass via URI scheme and types the password automatically
5. After unlocking, it re-encrypts the password on the stick with a fresh AES-256 key

---

## Security

EnpassUnlocker was designed with several layers of protection:

### 🔑 Windows DPAPI Key Protection
The AES-256 encryption key is never stored in plaintext. It is protected using the **Windows Data Protection API (DPAPI)**, which binds the key to your Windows user account. This means:
- Even if someone steals the `crypt_key.enc` file from `%APPDATA%\EnpassUnlocker\`, they cannot decrypt it on another machine or under a different user account
- The key file is useless without access to your exact Windows user session

### 🔒 AES-256-GCM Encryption
The master password stored on the USB stick is encrypted with **AES-256 in GCM mode**, which provides both confidentiality and integrity verification. Any tampering with the encrypted file will be detected.

### 🔄 Rolling Key Rotation
Every time the stick is used to unlock Enpass, the password is re-encrypted with a **brand new random key**. This means the ciphertext on the stick changes with every use.

### 🚫 No Clipboard Usage
The master password is **never copied to the clipboard**. Instead, it is typed character by character using `pyautogui`, making it invisible to clipboard monitors or sniffers running in the background.

### 🔗 Two-Factor Requirement
To unlock your vault, an attacker would need **both**:
- Physical access to your USB stick (the encrypted password)
- Access to your Windows user session (the DPAPI-protected key)

---

## Setup

### 1. Prerequisites

- Windows 10 or 11
- Python 3.10+ (or use the prebuilt `.exe`)
- Enpass installed

### 2. Install Python dependencies (if running from source)

```bash
pip install psutil pywin32 pyautogui cryptography
```

### 3. Create `settings.json`

Place a `settings.json` file in the same directory as the script/exe:

```json
{
    "SECURE_USB_DEVICE_NAME": "MY_USB_LABEL",
    "PWD_FILE": "enpass-key.enpass"
}
```

- `SECURE_USB_DEVICE_NAME` — the volume label of your USB stick (right-click the drive in Explorer → Properties to find or set it)
- `PWD_FILE` — the filename on the USB stick that contains your master password
- `FOCUS_TIMEOUT_SECONDS` - how long is waited at max for the Enpass window-focus
- `POST_FOCUS_DELAY_SECONDS` - time after foxus before autofill starts
- `TYPE_INTERVAL` - determines how fast the autofill is typing

### 4. Create the password file on the USB stick

Create a plain text file on your USB stick (e.g. `enpass-key.enpass`) and put your Enpass master password in it — nothing else, no newline.

On first use, EnpassUnlocker will automatically encrypt this file. From that point on, the plaintext is gone.

### 5. Run

```bash
python enpassunlock.py
```

Or double-click the `.exe` if you built it. The tool will scan for your USB stick and unlock Enpass as soon as it is detected.

---

## Building with auto-py-to-exe

You can compile EnpassUnlocker into a standalone `.exe` using [auto-py-to-exe](https://github.com/brentvollebregt/auto-py-to-exe).

### Install auto-py-to-exe

```bash
pip install auto-py-to-exe
auto-py-to-exe
```

### Recommended settings

| Setting | Value |
|---|---|
| Script Location | `enpassunlock.py` |
| Onefile | ✅ One File |
| Console Window | Console Based (so you can see status output) |
| Additional Files | Add `settings.json` via the "Additional Files" section |

### Hidden imports

Some packages are not auto-detected by PyInstaller. Add these under **Advanced > Hidden Imports**:

```
win32api
win32crypt
win32con
pywintypes
cryptography
pyautogui
psutil
```

### After building

- Copy the generated `.exe` to wherever you want to run it from
- Make sure `settings.json` is in the same directory as the `.exe` (if you didn't bundle it)
- The `crypt_key.enc` will be stored in `%APPDATA%\EnpassUnlocker\` automatically

---

## ⚠️ Disclaimer

This tool stores your Enpass master password in encrypted form on a USB stick. While multiple security layers are in place, **no system is 100% secure**.

- Always keep a secure backup of your master password somewhere safe (e.g. written down and stored physically)
- Do not lose your USB stick without having your master password memorized or backed up
- This tool is provided as-is, without any warranty
