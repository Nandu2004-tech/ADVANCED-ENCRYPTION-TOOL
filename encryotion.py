import os
import sys
import hmac
import hashlib
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QFileDialog, QMessageBox
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

# Secure Key Derivation Function (PBKDF2)
def derive_key(password, salt, key_length=32, iterations=100000):
    return PBKDF2(password, salt, dkLen=key_length, count=iterations)

# Generate HMAC for Integrity Verification
def generate_hmac(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()

# Encrypt a File
def encrypt_file(input_file, output_file, password):
    try:
        salt = get_random_bytes(16)
        key = derive_key(password.encode(), salt)
        cipher = AES.new(key, AES.MODE_CBC)
        iv = cipher.iv

        with open(input_file, 'rb') as f:
            plaintext = f.read()

        # Padding (PKCS7)
        padding_length = 16 - (len(plaintext) % 16)
        plaintext += bytes([padding_length]) * padding_length

        ciphertext = cipher.encrypt(plaintext)
        hmac_signature = generate_hmac(key, ciphertext)

        with open(output_file, 'wb') as f:
            f.write(salt + iv + hmac_signature + ciphertext)

        print(f"✔️ Encrypted: {input_file} → {output_file}")
        return True

    except Exception as e:
        print(f"❌ Encryption Error: {e}")
        return False

# Decrypt a File
def decrypt_file(input_file, output_file, password):
    try:
        with open(input_file, 'rb') as f:
            salt = f.read(16)
            iv = f.read(16)
            stored_hmac = f.read(32)
            ciphertext = f.read()

        key = derive_key(password.encode(), salt)
        calculated_hmac = generate_hmac(key, ciphertext)

        # Verify HMAC (integrity check)
        if not hmac.compare_digest(stored_hmac, calculated_hmac):
            print("⚠️ Warning: File integrity check failed! Possible corruption or tampering.")
            return False

        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext)

        # Remove padding
        padding_length = plaintext[-1]
        plaintext = plaintext[:-padding_length]

        with open(output_file, 'wb') as f:
            f.write(plaintext)

        print(f"✔️ Decrypted: {input_file} → {output_file}")
        return True

    except Exception as e:
        print(f"❌ Decryption Error: {e}")
        return False

# GUI Class
class EncryptionApp(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.file_path = None
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Advanced Encryption Tool")
        self.setGeometry(300, 300, 400, 200)

        self.select_file_btn = QtWidgets.QPushButton("Select File", self)
        self.encrypt_btn = QtWidgets.QPushButton("Encrypt", self)
        self.decrypt_btn = QtWidgets.QPushButton("Decrypt", self)
        self.exit_btn = QtWidgets.QPushButton("Exit", self)

        self.select_file_btn.clicked.connect(self.select_file)
        self.encrypt_btn.clicked.connect(self.encrypt_file)
        self.decrypt_btn.clicked.connect(self.decrypt_file)
        self.exit_btn.clicked.connect(self.close)

        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.select_file_btn)
        layout.addWidget(self.encrypt_btn)
        layout.addWidget(self.decrypt_btn)
        layout.addWidget(self.exit_btn)

        self.setLayout(layout)

    def select_file(self):
        self.file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if self.file_path:
            QMessageBox.information(self, "File Selected", f"Selected File: {self.file_path}")

    def encrypt_file(self):
        if not self.file_path:
            QMessageBox.warning(self, "Error", "No file selected!")
            return
        password, ok = QtWidgets.QInputDialog.getText(self, "Enter Password", "Enter encryption password:", QtWidgets.QLineEdit.Password)
        if ok and password:
            output_file = self.file_path + ".enc"
            if encrypt_file(self.file_path, output_file, password):
                QMessageBox.information(self, "Success", f"Encrypted File: {output_file}")

    def decrypt_file(self):
        if not self.file_path:
            QMessageBox.warning(self, "Error", "No file selected!")
            return
        password, ok = QtWidgets.QInputDialog.getText(self, "Enter Password", "Enter decryption password:", QtWidgets.QLineEdit.Password)
        if ok and password:
            output_file = self.file_path.replace(".enc", "_decrypted")
            if decrypt_file(self.file_path, output_file, password):
                QMessageBox.information(self, "Success", f"Decrypted File: {output_file}")

# CLI Mode
def cli_mode():
    import argparse
    parser = argparse.ArgumentParser(description="Advanced Encryption Tool (AES-256)")
    parser.add_argument("-e", "--encrypt", help="Encrypt a file", metavar="FILE")
    parser.add_argument("-d", "--decrypt", help="Decrypt a file", metavar="FILE")
    args = parser.parse_args()

    if args.encrypt:
        password = input("Enter encryption password: ")
        output_file = args.encrypt + ".enc"
        encrypt_file(args.encrypt, output_file, password)

    elif args.decrypt:
        password = input("Enter decryption password: ")
        output_file = args.decrypt.replace(".enc", "_decrypted")
        decrypt_file(args.decrypt, output_file, password)

    else:
        print("Use -e <file> to encrypt or -d <file> to decrypt.")

# Entry Point
if __name__ == '__main__':
    if len(sys.argv) > 1:
        cli_mode()
    else:
        app = QtWidgets.QApplication(sys.argv)
        window = EncryptionApp()
        window.show()
        sys.exit(app.exec_())
