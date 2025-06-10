import sys
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget, 
                            QVBoxLayout, QHBoxLayout, QPushButton, QLabel, 
                            QLineEdit, QFileDialog, QMessageBox)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QIcon
import os
from main_app.pades_signer.pades_signer import PAdESSigner

class PAdESApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.signer = PAdESSigner()
        self.signer.set_status_callback(self.update_status)
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("PAdES Signature Tool")
        self.setGeometry(100, 100, 800, 600)
        
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout()
        main_widget.setLayout(layout)
        
        tabs = QTabWidget()
        
        sign_tab = self.create_sign_tab()
        verify_tab = self.create_verify_tab()
        
        tabs.addTab(sign_tab, "Sign Document")
        tabs.addTab(verify_tab, "Verify Document")
        
        layout.addWidget(tabs)
        
        self.check_pendrive_timer = QTimer()
        self.check_pendrive_timer.timeout.connect(self.update_pendrive_status)
        self.check_pendrive_timer.start(1000)

    def create_sign_tab(self):
        sign_tab = QWidget()
        layout = QVBoxLayout()
        
        self.pendrive_status = QLabel("Waiting for pendrive...")
        layout.addWidget(self.pendrive_status)
        
        pin_layout = QHBoxLayout()
        pin_label = QLabel("Enter PIN:")
        self.pin_input = QLineEdit()
        self.pin_input.setEchoMode(QLineEdit.Password)
        pin_layout.addWidget(pin_label)
        pin_layout.addWidget(self.pin_input)
        layout.addLayout(pin_layout)
        
        select_file_btn = QPushButton("Select PDF to Sign")
        select_file_btn.clicked.connect(self.select_pdf_to_sign)
        layout.addWidget(select_file_btn)
        
        self.selected_file_label = QLabel("No file selected")
        layout.addWidget(self.selected_file_label)
        
        sign_button = QPushButton("Sign Document")
        sign_button.clicked.connect(self.sign_document)
        layout.addWidget(sign_button)
        
        self.status_label = QLabel("")
        layout.addWidget(self.status_label)
        
        layout.addStretch()
        sign_tab.setLayout(layout)
        return sign_tab

    def create_verify_tab(self):
        verify_tab = QWidget()
        layout = QVBoxLayout()
        
        select_verify_file_btn = QPushButton("Select PDF to Verify")
        select_verify_file_btn.clicked.connect(self.select_pdf_to_verify)
        layout.addWidget(select_verify_file_btn)
        
        self.verify_file_label = QLabel("No file selected")
        layout.addWidget(self.verify_file_label)
        
        select_key_btn = QPushButton("Select Public Key")
        select_key_btn.clicked.connect(self.select_public_key)
        layout.addWidget(select_key_btn)
        
        self.public_key_label = QLabel("No public key selected")
        layout.addWidget(self.public_key_label)
        
        verify_button = QPushButton("Verify Document")
        verify_button.clicked.connect(self.verify_document)
        layout.addWidget(verify_button)
        
        self.verify_status_label = QLabel("")
        layout.addWidget(self.verify_status_label)
        
        layout.addStretch()
        verify_tab.setLayout(layout)
        return verify_tab

    def select_pdf_to_sign(self):
        file_name, _ = QFileDialog.getOpenFileName(
            self, "Select PDF Document", "", "PDF Files (*.pdf)")
        if file_name:
            self.selected_file_path = file_name
            self.selected_file_label.setText(f"Selected file: {os.path.basename(file_name)}")

    def sign_document(self):
        self.signer.set_status_callback(self.update_status)
        if not hasattr(self, 'selected_file_path'):
            QMessageBox.warning(self, "Warning", "Please select a file first")
            return
            
        if not self.signer.private_key_path:
            QMessageBox.warning(self, "Warning", "No pendrive with private key detected")
            return
            
        pin = self.pin_input.text()
        if not pin:
            QMessageBox.warning(self, "Warning", "Please enter PIN")
            return
            
        success = self.signer.sign_document(self.selected_file_path, pin)
        if success:
            QMessageBox.information(self, "Success", "Document signed successfully")
        else:
            QMessageBox.critical(self, "Error", "Failed to sign document")

    def verify_document(self):
        self.signer.set_status_callback(self.update_verify_status)
        if not hasattr(self, 'verify_file_path') or not hasattr(self, 'public_key_path'):
            QMessageBox.warning(self, "Warning", "Please select both a file and a public key")
            return
            
        success = self.signer.verify_document(self.verify_file_path, self.public_key_path)
        if success:
            QMessageBox.information(self, "Success", "Document verified successfully")
        else:
            QMessageBox.critical(self, "Error", "Failed to verify document")

    def select_pdf_to_verify(self):
        file_name, _ = QFileDialog.getOpenFileName(
            self, "Select PDF Document", "", "PDF Files (*.pdf)")
        if file_name:
            self.verify_file_path = file_name
            self.verify_file_label.setText(f"Selected file: {os.path.basename(file_name)}")

    def select_public_key(self):
        file_name, _ = QFileDialog.getOpenFileName(
            self, "Select Public Key", "", "PEM Files (public_key.pem)")
        if file_name:
            if os.path.basename(file_name) != "public_key.pem":
                QMessageBox.warning(self, "Warning", "Please select a file named 'public_key.pem'")
                return
            self.public_key_path = file_name
            self.public_key_label.setText(f"Selected key: {os.path.basename(file_name)}")

    def update_pendrive_status(self):
        self.signer.check_for_pendrive()
        if self.signer.private_key_path:
            self.pendrive_status.setText(f"Pendrive found: {self.signer.pendrive_path}\nPrivate key found: {os.path.basename(self.signer.private_key_path)}")
            self.pendrive_status.setStyleSheet("color: green")
        elif self.signer.pendrive_path:
            self.pendrive_status.setText(f"Pendrive found: {self.signer.pendrive_path}\nNo valid private key found")
            self.pendrive_status.setStyleSheet("color: orange")
        else:
            self.pendrive_status.setText("No pendrive detected")
            self.pendrive_status.setStyleSheet("color: red")

    def update_status(self, message):
        self.status_label.setText(message)

    def update_verify_status(self, message):
        self.verify_status_label.setText(message)