import sys
import time
import os
from hashlib import sha256
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton
from PyQt5.QtCore import Qt, QThread, pyqtSignal


def generate(pin, progress_callback):
    if not pin or len(pin.strip()) == 0:
        progress_callback.emit("Error: Password cannot be empty")
        return

    progress_callback.emit("Hashing PIN…")
    key_from_pin = sha256(pin.encode()).digest()
    print("Hash pinu 256-bit: ", key_from_pin)

    progress_callback.emit("Generating RSA key…")
    rsa_key_pair = RSA.generate(4096)
    rsa_private_key = rsa_key_pair.export_key()
    rsa_public_key = rsa_key_pair.publickey().export_key()
    rsa_key_padded = pad(rsa_private_key, AES.block_size)
    print("Prywatny klucz RSA 4096-bit: ", rsa_key_padded)


    progress_callback.emit("Encrypting RSA key…")
    cipher = AES.new(key_from_pin, AES.MODE_ECB)
    rsa_key_encrypted = cipher.encrypt(rsa_key_padded)
    
    with open('encrypted_private_key.bin', 'wb') as f:
        f.write(rsa_key_encrypted)
    print("Zaszyfrowany klucz prywatny: ", rsa_key_encrypted.hex())

    progress_callback.emit("Saving public key…")
    with open('public_key.pem', 'wb') as f:
        f.write(rsa_public_key)
    print("Klucz publiczny: ", rsa_public_key.decode())

    progress_callback.emit("Done. Saved to encrypted_private_key.bin and public_key.pem")

    try:
        decrypt_cipher = AES.new(key_from_pin, AES.MODE_ECB)
        decrypted_padded = decrypt_cipher.decrypt(rsa_key_encrypted)
        decrypted_key = unpad(decrypted_padded, AES.block_size)
        print("Verification successful - key can be decrypted")
    except Exception as e:
        print(f"Warning: Verification failed - {str(e)}")


class WorkerThread(QThread):
    progress_signal = pyqtSignal(str)
    def __init__(self, text):
        super().__init__()
        self.text = text
    def run(self):
        generate(self.text, self.progress_signal)


class App(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('RSA keys generator')
        self.setFixedSize(600, 200)
        layout = QVBoxLayout()

        label = QLabel('2nd auxiliary application for generating RSA keys')
        label.setAlignment(Qt.AlignCenter)
        layout.addWidget(label)

        self.text_input = QLineEdit()
        self.text_input.setEchoMode(QLineEdit.Password)
        self.text_input.setPlaceholderText('Enter your password')
        layout.addWidget(self.text_input)
        self.text_input.returnPressed.connect(self.on_click)

        button = QPushButton('Generate')
        button.clicked.connect(self.on_click)
        layout.addWidget(button)

        self.progress_label = QLabel('Ready')
        self.progress_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.progress_label)

        self.setLayout(layout)

        self.setStyleSheet("""
            QWidget {
                background-color: #1e1e1e;
                color: #e0e0e0;
            }
            QLabel {
                font-size: 20px;
                font-family: Arial;
                font-weight: bold;
                padding: 10px;
            }
            QLineEdit {
                background-color: #2d2d2d;
                border: 2px solid #404040;
                border-radius: 8px;
                padding: 8px;
                font-size: 14px;
                color: #ffffff;
            }
            QLineEdit:hover {
                border: 2px solid #606060;
                background-color: #353535;
            }
            QPushButton {
                background-color: #3a3a3a;
                border: none;
                border-radius: 10px;
                padding: 12px;
                font-size: 16px;
                font-family: Arial;
                color: #ffffff;
            }
            QPushButton:hover {
                background-color: #505050;
                box-shadow: 0px 0px 10px #606060;
            }
            QPushButton:pressed {
                background-color: #2a2a2a;
            }
            QLabel#progress_label {
                font-size: 14px;
                font-weight: normal;
                color: #a0a0a0;
            }
        """)

        self.progress_label.setObjectName("progress_label")


    def on_click(self):
        text = self.text_input.text()
        self.worker = WorkerThread(text)
        self.worker.progress_signal.connect(self.update_progress)
        self.worker.start()


    def update_progress(self, message):
        self.progress_label.setText(message)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = App()
    ex.show()
    sys.exit(app.exec_())
