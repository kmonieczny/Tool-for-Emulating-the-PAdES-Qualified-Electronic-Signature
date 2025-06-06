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

# === ŚCIEŻKI I GLOBALNA FLAG ===

usb_drive = "D:\\"
key_file_name = "encrypted_private_key.bin"
key_file_path = os.path.join(usb_drive, key_file_name)

encrypted_key_path = os.path.join(usb_drive, "encrypted_private_key.bin")
signed_pdf_output = 'plik_podpisany.pdf'

key_detected = threading.Event()


# === WĄTEK DO WYKRYWANIA PENDRIVE'A ===

def monitor_usb():
    print("Czekam na podłączenie pendrive'a i pliku 'encrypted_private_key.bin'...")
    while True:
        if os.path.exists(key_file_path):
            print("[INFO] Wykryto plik 'encrypted_private_key.bin' na pendrive (D:\\)")
            key_detected.set()
            break
        time.sleep(2)


# === GŁÓWNA FUNKCJA (URUCHAMIANA PO POTWIERDZENIU) ===

def process_signature():
    a1 = False
    while not a1:
        pin = input("Podaj PIN do odszyfrowania klucza: ")
        try:
            print("[*] Odczytuję i odszyfrowuję klucz...")
            key_from_pin = SHA256.new(pin.encode()).digest()
            with open(encrypted_key_path, 'rb') as f:
                encrypted_key = f.read()
            cipher = AES.new(key_from_pin, AES.MODE_ECB)
            decrypted_padded_key = cipher.decrypt(encrypted_key)
            decrypted_key = unpad(decrypted_padded_key, AES.block_size)
            rsa_key = RSA.import_key(decrypted_key)
            print("[*] Klucz odszyfrowany.")
            a1 = True
        except Exception as e:
            print("Błąd odszyfrowywania klucza:", e)

    # Konwersja do obiektu cryptography
    try:
        der_key = rsa_key.export_key(format='DER')
        private_key_crypto = serialization.load_der_private_key(
            der_key,
            password=None,
            backend=default_backend()
        )
    except Exception as e:
        print("Błąd konwersji klucza:", e)
        return

    # Generowanie certyfikatu
    try:
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

    except Exception as e:
        print("Błąd generowania certyfikatu:", e)
        return

    # Podpisanie PDF
    try:
        signer = signers.SimpleSigner.load(
            key_file='key.pem',
            cert_file='cert.pem',
        )

        meta = PdfSignatureMetadata(field_name='Signature1')
        pdf_to_sign = input("Podaj ścieżkę do pliku PDF: ")

        with open(pdf_to_sign, 'rb') as inf:
            pdf_writer = IncrementalPdfFileWriter(inf)
            pdf_signed = signers.sign_pdf(
                pdf_writer,
                signature_meta=meta,
                signer=signer,
                existing_fields_only=False,
            )

        with open(signed_pdf_output, 'wb') as outf:
            outf.write(pdf_signed.getvalue())

        os.remove('key.pem')
        os.remove('cert.pem')

        print(f"\n[*] Gotowe! Plik podpisany: {signed_pdf_output}")

    except Exception as e:
        print("Błąd podpisywania PDF:", e)


# === START ===

# Uruchomienie wątku
threading.Thread(target=monitor_usb, daemon=True).start()

# Czekaj na wykrycie pendrive'a
key_detected.wait()

# Prośba o potwierdzenie przed podpisaniem
input("\n[OK] Pendrive wykryty. Naciśnij Enter, aby kontynuować podpisywanie...")

# Start procesu podpisywania
process_signature()
