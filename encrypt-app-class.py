import sys

import base64


from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from PyQt5.QtCore import QSize, Qt
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QVBoxLayout, QHBoxLayout, QLineEdit, QGroupBox, QLabel, QGridLayout, QTextEdit, QMainWindow, QPlainTextEdit,QFileDialog
from PyQt5.QtGui import QPalette, QColor


# Subclass QMainWindow to customize your application's main window
class MainWindow(QMainWindow):
    def __init__(self):
        super(MainWindow, self).__init__()

        self.setWindowTitle("Encrypt")

        mainlayout = QGridLayout()

        # Create Key Generation Box
        keyGeneration = QGroupBox('Key Generation')
        self.keyGenerationButton = QPushButton('Click for a new pair of keys')
        self.keyGenerationLabel = QLabel()
        # Layout Key Generation Box
        layoutKeyGeneration = QHBoxLayout()
        layoutKeyGeneration.addWidget(self.keyGenerationButton)
        layoutKeyGeneration.addWidget(self.keyGenerationLabel)
        keyGeneration.setLayout(layoutKeyGeneration)

        # Key Generation Action
        self.keyGenerationButton.clicked.connect(self.keyGeneration)

        # Create Encrypt Box
        encryptBox = QGroupBox('Encrypt')
        self.publicKeyLabel = QLabel('File Path of Public Key')
        self.publicKey = QLineEdit()
        self.encryptTextLabel = QLabel('Text to Encrypt')
        self.encryptText = QTextEdit()
        self.encryptButton = QPushButton('Click to Encrypt')
        self.publicKeyFileButton = QPushButton('Select Public Key')
       
        # Layout Encrypt Box
        layoutEncrypt = QVBoxLayout()
        layoutEncrypt.addWidget(self.publicKeyLabel)
        layoutEncrypt.addWidget(self.publicKey)
        layoutEncrypt.addWidget(self.publicKeyFileButton)
        layoutEncrypt.addSpacing(10)
        layoutEncrypt.addWidget(self.encryptTextLabel)
        layoutEncrypt.addWidget(self.encryptText)
        layoutEncrypt.addSpacing(20)
        layoutEncrypt.addWidget(self.encryptButton)
        layoutEncrypt.addStretch(1)
        encryptBox.setLayout(layoutEncrypt)

        # Create Decrypt Box
        decryptBox = QGroupBox('Decrypt')
        self.privateKeyLabel = QLabel('File Path of Private Key')
        self.privateKey = QLineEdit()
        self.decryptTextLabel = QLabel('Text to Decrypt')
        self.decryptText = QTextEdit()
        self.decryptButton = QPushButton('Click to Decrypt')
        # Layout Decrypt Box
        layoutDecrypt = QVBoxLayout()
        layoutDecrypt.addWidget(self.privateKeyLabel)
        layoutDecrypt.addWidget(self.privateKey)
        layoutDecrypt.addSpacing(10)
        layoutDecrypt.addWidget(self.decryptTextLabel)
        layoutDecrypt.addWidget(self.decryptText)
        layoutDecrypt.addSpacing(20)
        layoutDecrypt.addWidget(self.decryptButton)
        layoutDecrypt.addStretch(1)
        decryptBox.setLayout(layoutDecrypt)

        # Create Result Box
        resultBox = QGroupBox('Result')
        self.resultLabel = QTextEdit()
        # Layout Result Box
        layoutResult = QVBoxLayout()
        layoutResult.addWidget(self.resultLabel)
        layoutResult.addStretch(1)
        resultBox.setLayout(layoutResult)

        self.resultLabel.setPlainText("Result will appear here")

        # Encrypt and Decrypt Action
        self.encryptButton.clicked.connect(self.clickEncrypt)
        self.decryptButton.clicked.connect(self.clickDecrypt)
        self.publicKeyFileButton.clicked.connect(self.open_file_dialog)

        # self.encryptText.textChanged.connect(self.resultLabel.setText)

        # Layout Main Window
        mainlayout.addWidget(keyGeneration, 0, 0, 1, 2)
        mainlayout.addWidget(encryptBox, 1, 0)
        mainlayout.addWidget(decryptBox, 1, 1)
        mainlayout.addWidget(resultBox, 2, 0, 1, 2)
        mainlayout.setVerticalSpacing(30)
        widget = QWidget()
        widget.setLayout(mainlayout)
        self.setCentralWidget(widget)


    def open_file_dialog(self):
        file = QFileDialog.getOpenFileName()
        path = file[0]
        print(path)    

    # Action to Encrypt
    def clickEncrypt(self):
        text = self.encryptText.toPlainText()
        binaryText = text.encode('ascii')
        public_key_path = self.publicKey.text()
        with open(public_key_path, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
        encrypted = public_key.encrypt(
            binaryText,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        b64_string = str(base64.b64encode(encrypted),'utf-8')
        self.resultLabel.setPlainText(b64_string)
        # print(self.textEncrypt)

    # Action to Decrypt
    def clickDecrypt(self):
        text = self.decryptText.toPlainText()
        binaryEncrypted = base64.b64decode(text)
        private_key_path = self.privateKey.text()
        with open(private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        original_message = private_key.decrypt(
            binaryEncrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        original = original_message.decode('utf-8')
        self.resultLabel.setPlainText(original)
        # print(self.textDecrypt)
    
    # Action to Generate Key Pairs
    def keyGeneration(self):
        ## Generate public and private key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        ## Write private key to file
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        # pem.splitlines()[2]
        with open('private_key.pem', 'wb') as f:
            f.write(pem)

        ## Write public key to file
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open('public_key.pem', 'wb') as f:
            f.write(pem)

        # Make notes to user
        self.keyGenerationButton.setText('Already generated.')
        self.keyGenerationButton.setDisabled(True)
        self.keyGenerationLabel.setText('New pair of keys saved to pem files.')
        

app = QApplication(sys.argv)

window = MainWindow()
window.show()

app.exec()