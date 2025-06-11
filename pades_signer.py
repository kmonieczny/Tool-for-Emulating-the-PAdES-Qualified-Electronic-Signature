import threading, time, os, hashlib, io
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import unpad
from Crypto.PublicKey import RSA
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime
from PyPDF2 import PdfReader, PdfWriter


class PAdESSigner:
    def __init__(self):
        self.pendrive_path = None
        self.private_key_path = None
        self.status_callback = None
        self.key_detected = threading.Event()
        self.monitor_thread = threading.Thread(target=self.monitor_usb, daemon=True)
        self.monitor_thread.start()

    def set_status_callback(self, callback):
        self.status_callback = callback

    def update_status(self, message):
        if self.status_callback:
            self.status_callback(message)

    def check_for_pendrive(self):
        drives = ['D:\\', 'E:\\', 'F:\\', 'G:\\', 'H:\\']
        for drive in drives:
            if os.path.exists(drive):
                key_path = os.path.join(drive, "encrypted_private_key.bin")
                if os.path.exists(key_path):
                    try:
                        with open(key_path, 'rb') as f:
                            data = f.read()
                            if len(data) > 28:
                                self.pendrive_path = drive
                                self.private_key_path = key_path
                                return True
                    except:
                        continue
        self.pendrive_path = None
        self.private_key_path = None
        return False

    def monitor_usb(self):
        while True:
            self.check_for_pendrive()
            time.sleep(2)


    def sign_document(self, pdf_path, pin):
        try:
            if not self.private_key_path or not os.path.exists(self.private_key_path):
                self.update_status("Error: Private key not found on pendrive")
                return False


            self.update_status("Reading and decrypting key...")
            try:
                key_from_pin = SHA256.new(pin.encode()).digest()
                with open(self.private_key_path, 'rb') as f:
                    encrypted_key = f.read()
                cipher = AES.new(key_from_pin, AES.MODE_ECB)
                decrypted_padded_key = cipher.decrypt(encrypted_key)
                decrypted_key = unpad(decrypted_padded_key, AES.block_size)
                RSA.import_key(decrypted_key)

                self.update_status("Key decrypted successfully.")
            except ValueError as e:
                if 'MAC check failed' in str(e):
                    self.update_status("Error: Incorrect PIN")
                else:
                    self.update_status(f"Error during signing: {str(e)}")
                return False

            private_key = load_pem_private_key(decrypted_key, password=None)
            pdf_writer = PdfWriter()
            for a in PdfReader(pdf_path).pages: pdf_writer.add_page(a)

            signed_stream = io.BytesIO()
            pdf_writer.write(signed_stream)
            signed_stream.seek(0)
            hash = hashlib.sha256(signed_stream.read()).digest()

            pdf_writer.add_metadata({
                '/Author': "Name Surname",
                '/Organisation': "PG",
                '/DigitalSignature': private_key.sign(hash, padding.PKCS1v15(), hashes.SHA256()).hex()
            })

            signed_pdf_path = os.path.splitext(pdf_path)[0] + '_signed.pdf'
            with open(signed_pdf_path, "wb") as output_file:
                pdf_writer.write(output_file)

            self.update_status(f"Document signed successfully: {signed_pdf_path}")
            return True

        except Exception as e:
            self.update_status(f"Error during signing: {str(e)}")
            return False




    def verify_document(self, pdf_path, public_key_path):
        try:
            self.update_status("Verifying document...")

            with open(public_key_path, "rb") as key_file:
                public_key = serialization.load_pem_public_key(key_file.read())


            data = ['/DigitalSignature', '/Author', '/Organisation']
            metadata = PdfReader(pdf_path).metadata
            pdf_data = []
            for i in data:
                if i in metadata:
                    pdf_data.append(metadata[i])

            if not pdf_data or pdf_data[0] == "" or pdf_data[1] == "" or pdf_data[2] == "":
                self.update_status("No signature")
                return False

            pdf_writer = PdfWriter()
            for a in PdfReader(pdf_path).pages: pdf_writer.add_page(a)
            temp_metadata = PdfReader(pdf_path).metadata.copy()
            for i in data:
                if i in temp_metadata: del temp_metadata[i]
            pdf_writer.add_metadata(temp_metadata)


            signed_stream = io.BytesIO()
            pdf_writer.write(signed_stream)
            signed_stream.seek(0)
            hash = hashlib.sha256(signed_stream.read()).digest()

            try:
                public_key.verify(bytes.fromhex(pdf_data[0]), hash, padding.PKCS1v15(), hashes.SHA256())

                self.update_status(f"Signature valid!\n{pdf_data[1]}\n{pdf_data[2]}")
                return True

            except InvalidSignature:
                self.update_status("Signature verification failed")
                return False
            except Exception as e:
                self.update_status(f"Error during verification: {str(e)}")
                return False


        except Exception as e:
            self.update_status(f"Error during verification: {str(e)}")
            return False
