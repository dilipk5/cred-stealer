#!/usr/bin/env python3
import json
import ctypes as ct
from base64 import b64decode
from pathlib import Path

def validprofile():
    """Find valid Firefox profile with logins.json"""
    root_file_paths = [
        "snap/firefox/common/.mozilla/firefox/*default*",
        ".mozilla/firefox/*default*"
    ]
    
    valid_profiles = []
    
    for pattern in root_file_paths:
        # Search for matching profile directories
        for profile_dir in Path.home().glob(pattern):
            if profile_dir.is_dir():
                # Check if logins.json exists
                logins_file = profile_dir / "logins.json"
                if logins_file.exists():
                    valid_profiles.append(profile_dir)
                    print(f"✓ Found valid profile: {profile_dir}")
    
    if not valid_profiles:
        raise FileNotFoundError("No Firefox profile with logins.json found!")
    
    # Return the first valid profile
    return valid_profiles[0]

# Usage
try:
    profile = validprofile()
    print(f"\nUsing profile: {profile}")
except FileNotFoundError as e:
    print(e)
    exit(1)

import ctypes as ct
import subprocess

def load_libnss():
    """Load libnss library - auto-detect location"""
    
    # Try to find it using system tools
    try:
        result = subprocess.run(
            ["ldconfig", "-p"], 
            capture_output=True, 
            text=True
        )
        for line in result.stdout.split('\n'):
            if 'libnss3.so' in line:
                path = line.split('=>')[1].strip()
                try:
                    return ct.CDLL(path)
                except:
                    continue
    except:
        pass
    
    # Fallback to common locations
    locations = [
        "/usr/lib/x86_64-linux-gnu/nss/libnss3.so",
        "/usr/lib/x86_64-linux-gnu/libnss3.so",
        "/usr/lib/firefox/libnss3.so",
        "/usr/lib/libnss3.so",
        "/usr/lib64/libnss3.so",
        "libnss3.so",  # Let system find it
    ]
    
    for path in locations:
        try:
            return ct.CDLL(path)
        except:
            continue
    
    raise Exception("libnss3.so not found! Install: sudo apt install libnss3")

# Use it
libnss = load_libnss()

class SECItem(ct.Structure):
    _fields_ = [("type", ct.c_uint), ("data", ct.c_void_p), ("len", ct.c_uint)]

libnss.NSS_Init.argtypes = [ct.c_char_p]
libnss.PK11SDR_Decrypt.argtypes = [ct.POINTER(SECItem), ct.POINTER(SECItem), ct.c_void_p]
libnss.NSS_Init(f"sql:{profile}".encode())

def decrypt(enc):
    data = b64decode(enc)
    inp = SECItem(0, ct.cast(ct.c_char_p(data), ct.c_void_p), len(data))
    out = SECItem(0, None, 0)
    libnss.PK11SDR_Decrypt(ct.byref(inp), ct.byref(out), None)
    # print ("data",data)
    # print ("inp",inp)
    # print ("out",out)
    # print("return value is: ",ct.string_at(out.data, out.len).decode() )
    return ct.string_at(out.data, out.len).decode()

# Read logins
with open(profile / "logins.json") as f:
    logins = json.load(f)

# Create output with encrypted AND decrypted
def getcreds():
    output = []
    for demo in logins['logins']:

        output.append({
            'url':demo['hostname'],
            'uname':decrypt(demo['encryptedUsername']),
            'pass':decrypt(demo['encryptedPassword'])
        })
    return output
