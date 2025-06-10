import threading
import time
import os
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import unpad
from Crypto.PublicKey import RSA
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta, timezone
from pyhanko.sign import signers
from pyhanko.sign.fields import SigFieldSpec, append_signature_field
from pyhanko.sign.general import load_cert_from_pemder
from pyhanko.sign.signers import PdfSignatureMetadata
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko.sign.fields import enumerate_sig_fields

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
            key_from_pin = SHA256.new(pin.encode()).digest()
            
            with open(self.private_key_path, 'rb') as f:
                data = f.read()

            nonce = data[:12]
            tag = data[12:28]
            encrypted_key = data[28:]

            cipher = AES.new(key_from_pin, AES.MODE_GCM, nonce=nonce)
            try:
                decrypted_padded_key = cipher.decrypt_and_verify(encrypted_key, tag)
                decrypted_key = unpad(decrypted_padded_key, AES.block_size)
            except ValueError as e:
                if 'MAC check failed' in str(e):
                    self.update_status("Error: Incorrect PIN")
                else:
                    self.update_status(f"Error during signing: {str(e)}")
                return False
            rsa_key = RSA.import_key(decrypted_key)
            self.update_status("Key decrypted successfully.")

            der_key = rsa_key.export_key(format='DER')
            private_key_crypto = serialization.load_der_private_key(
                der_key,
                password=None,
                backend=default_backend()
            )

            self.update_status("Generating certificate...")
            common_name = "User Certificate"
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            ])
            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(private_key_crypto.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.now(timezone.utc))
                .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
                .add_extension(
                    x509.BasicConstraints(ca=True, path_length=None),
                    critical=True,
                )
                .sign(private_key_crypto, hashes.SHA256(), default_backend())
            )

            with open('key.pem', 'wb') as f:
                f.write(private_key_crypto.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                ))

            with open('cert.pem', 'wb') as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))

            self.update_status("Signing PDF...")
            signer = signers.SimpleSigner.load(
                key_file='key.pem',
                cert_file='cert.pem',
            )

            meta = PdfSignatureMetadata(field_name='Signature1')
            output_path = os.path.splitext(pdf_path)[0] + '_signed.pdf'

            with open(pdf_path, 'rb') as inf:
                pdf_writer = IncrementalPdfFileWriter(inf)
                pdf_signed = signers.sign_pdf(
                    pdf_writer,
                    signature_meta=meta,
                    signer=signer,
                    existing_fields_only=False,
                )

            with open(output_path, 'wb') as outf:
                outf.write(pdf_signed.getvalue())

            os.remove('key.pem')
            os.remove('cert.pem')

            self.update_status(f"Document signed successfully: {output_path}")
            return True

        except Exception as e:
            self.update_status(f"Error during signing: {str(e)}")
            return False

    def verify_document(self, pdf_path, public_key_path):
        try:
            self.update_status("Verifying document...")

            with open(public_key_path, 'rb') as f:
                public_key_data = f.read()

            with open(pdf_path, 'rb') as f:
                pdf_reader = PdfFileReader(f)
                sig_fields = list(enumerate_sig_fields(pdf_reader))
                if not sig_fields:
                    self.update_status("No signature fields found in the document.")
                    return False
                field_name = sig_fields[0][0]
            validation_result = validate_pdf_signature(pdf_path, field_name)
            if getattr(validation_result, 'trusted', False):
                signer_cert = getattr(validation_result, 'signer_cert', None)
                if signer_cert is not None:
                    provided_public_key = serialization.load_pem_public_key(public_key_data)
                    if signer_cert.public_key().public_numbers() == provided_public_key.public_numbers():
                        self.update_status("Document verified successfully - Signature is valid and matches the provided public key")
                        return True
                    else:
                        self.update_status("Signature is valid, but does NOT match the provided public key")
                        return False
                else:
                    self.update_status("Signature is valid, but could not extract signer's certificate for public key comparison")
                    return False
            else:
                self.update_status("Document verification failed - Invalid signature")
                return False
        except Exception as e:
            self.update_status(f"Error during verification: {str(e)}")
            return False
