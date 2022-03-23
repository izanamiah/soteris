import sys
import base64
import cryptography
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from PyQt5.QtCore import QSize
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QVBoxLayout, QHBoxLayout, QGroupBox, QLabel, QGridLayout, QTextEdit, QMainWindow,QFileDialog, QMessageBox


# Subclass QMainWindow to customize your application's main window
class MainWindow(QMainWindow):
    def __init__(self):
        super(MainWindow, self).__init__()

        self.setWindowTitle("Soteris Encrypt")

        mainlayout = QGridLayout()

        self.setFixedSize(QSize(600, 700))

        self.publicKeyPath = ""
        self.privateKeyPath = ""
        self.keyStorePath= ""

        # Create Key Generation Box
        keyGeneration = QGroupBox('Key Generation')
        self.keyGenerationButton = QPushButton('Generate Key Pair')
        self.keyGenerationButton.setDisabled(True)
        self.keyGenerationLabel = QLabel()
        self.keyStorePathButton = QPushButton('Select Path')
        # Layout Key Generation Box
        layoutKeyGeneration = QGridLayout()
        layoutKeyGeneration.addWidget(self.keyStorePathButton, 0 , 0)
        layoutKeyGeneration.addWidget(self.keyGenerationButton, 0, 1)
        layoutKeyGeneration.addWidget(self.keyGenerationLabel, 1, 0, 1, 2)
        keyGeneration.setLayout(layoutKeyGeneration)

        # Key Generation Action
        self.keyGenerationButton.clicked.connect(self.keyGeneration)
        self.keyStorePathButton.clicked.connect(self.openStorePathDialog)

        # Create Encrypt Box
        encryptBox = QGroupBox('Encrypt')
        # self.publicKeyLabel = QLabel('Public Key')
        self.publicKeyFileButton = QPushButton('Import Public Key')
        self.publicKey = QLabel()
        self.encryptTextLabel = QLabel('Text to Encrypt')
        self.encryptText = QTextEdit()
        self.encryptButton = QPushButton('Encrypt')

        # Layout Encrypt Box
        layoutEncrypt = QVBoxLayout()
        # layoutEncrypt.addWidget(self.publicKeyLabel)
        layoutEncrypt.addWidget(self.publicKeyFileButton)
        layoutEncrypt.addWidget(self.publicKey)
        layoutEncrypt.addSpacing(10)
        layoutEncrypt.addWidget(self.encryptTextLabel)
        layoutEncrypt.addWidget(self.encryptText)
        layoutEncrypt.addSpacing(20)
        layoutEncrypt.addWidget(self.encryptButton)
        layoutEncrypt.addStretch(1)
        encryptBox.setLayout(layoutEncrypt)

        # Create Decrypt Box
        decryptBox = QGroupBox('Decrypt')
        # self.privateKeyLabel = QLabel('File Path of Private Key')
        self.privateKeyFileButton = QPushButton('Import Private Key')
        self.privateKey = QLabel()
        self.decryptTextLabel = QLabel('Text to Decrypt')
        self.decryptText = QTextEdit()
        self.decryptButton = QPushButton('Decrypt')
        # Layout Decrypt Box
        layoutDecrypt = QVBoxLayout()
        # layoutDecrypt.addWidget(self.privateKeyLabel)
        layoutDecrypt.addWidget(self.privateKeyFileButton)
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

        self.publicKeyFileButton.clicked.connect(self.open_file_dialog_public)
        self.privateKeyFileButton.clicked.connect(self.open_file_dialog_private)

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

    def open_file_dialog_public(self):
        file = QFileDialog.getOpenFileName()
        path = file[0]
        fileName = path.split('/')[-1]
        # print(path)
        self.publicKeyPath = path
        self.publicKey.setText('Public Key Selected: '+fileName)

    def open_file_dialog_private(self):
        file = QFileDialog.getOpenFileName()
        path = file[0]
        fileName = path.split('/')[-1]
        # print(path)
        self.privateKeyPath = path
        self.privateKey.setText('Private Key Selected: '+fileName)

    def openStorePathDialog(self):
        path = QFileDialog.getExistingDirectory(self, "Select Directory")
        self.keyStorePath = path
        self.keyGenerationButton.setDisabled(False)
        self.keyGenerationLabel.setText('Path Selected: ' + path)
    

    # Action to Encrypt
    def clickEncrypt(self):
        if self.publicKeyPath=="":
            self.popMessage('Please select public key.')
        else:
            try:
                text = self.encryptText.toPlainText()
                #binaryText = text.encode('ascii')
                binaryText = text.encode('unicode-escape')
                with open(self.publicKeyPath, "rb") as key_file:
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
            except:
                self.popMessage('Unable to encrypt message.')

    # Action to Decrypt
    def clickDecrypt(self):
        if self.privateKeyPath=="":
            self.popMessage('Please select private key.')
        else:
            try:
                text = self.decryptText.toPlainText()
                binaryEncrypted = base64.b64decode(text)
                with open(self.privateKeyPath, "rb") as key_file:
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
                original = original_message.decode('unicode-escape')
                self.resultLabel.setPlainText(original)
                # print(self.textDecrypt)
            except:
                self.popMessage('Unable to decrypt message.')

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
        with open(self.keyStorePath+'/private_key.pem', 'wb') as f:
            f.write(pem)
        ## Write public key to file
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(self.keyStorePath+'/public_key.pem', 'wb') as f:
            f.write(pem)

        # Make notes to user
        self.keyGenerationButton.setText('Already generated.')
        self.keyGenerationButton.setDisabled(True)
        self.keyGenerationLabel.setText('New key pair saved to ' + self.keyStorePath)

    def popMessage(self, message):
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Information)
        msg.setText(message)
        msg.exec()


#app = QApplication(sys.argv)
#window = MainWindow()
#window.show()
#app.exec()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    app.exec()
