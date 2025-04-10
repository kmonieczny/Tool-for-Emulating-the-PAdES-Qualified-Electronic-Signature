from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
import os
import time
import platform
import sys


WINDOWS_SUPPORT = False
try:
    if platform.system().lower() == 'windows':
        print("Windows system detected, attempting to import win32 modules...")
        import win32api
        import win32file
        WINDOWS_SUPPORT = True
        print("win32api and win32file modules imported successfully")
    else:
        print(f"Non-Windows system detected: {platform.system()}")
except ImportError as e:
    print(f"Error importing Windows modules: {e}")
    print(f"Python path: {sys.path}")
    WINDOWS_SUPPORT = False
except Exception as e:
    print(f"Unexpected error while loading Windows modules: {e}")
    WINDOWS_SUPPORT = False

class PAdESSigner:
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.pendrive_path = None
        self.private_key_path = None

    def load_encrypted_private_key(self, key_path, pin):
        pass

    def sign_document(self, pdf_path):
        pass

    def verify_signature(self, pdf_path, public_key_path):
        pass

    def check_for_pendrive(self):
        if not WINDOWS_SUPPORT:
            print(f"Warning: Pendrive detection is not supported. System: {platform.system()}, Platform: {sys.platform}")
            return False

        try:
            print("Checking for removable drives...")
            drives = win32api.GetLogicalDriveStrings()
            drives = drives.split('\000')[:-1]
            print(f"Found drives: {drives}")
            
            for drive in drives:
                drive_type = win32file.GetDriveType(drive)
                print(f"Drive {drive} type: {drive_type}")
                if drive_type == win32file.DRIVE_REMOVABLE:
                    print(f"Found removable drive: {drive}")
                    self.pendrive_path = drive

                    key_file = self._find_private_key(drive)
                    if key_file:
                        self.private_key_path = key_file
                        print(f"Found private key at: {key_file}")
                        return True
            print("No removable drives with private keys found")
            return False
        except Exception as e:
            print(f"Error checking for pendrive: {e}")
            return False

    def _find_private_key(self, drive_path):
        try:
            key_files = ['encrypted_private_key.pem']
            print(f"Searching for private key in {drive_path}")
            
            for root, _, files in os.walk(drive_path):
                for file in files:
                    if file.lower() in key_files:
                        return os.path.join(root, file)
        except Exception as e:
            print(f"Error searching for private key: {e}")
        return None

    def verify_document(self):
        pass