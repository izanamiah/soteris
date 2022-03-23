import sys
from unittest import result
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QVBoxLayout, QLineEdit, QGroupBox, QLabel, QGridLayout, QTextEdit, QMainWindow
app = QApplication(sys.argv)
window = QWidget()#QMainWindow()b
mainlayout = QGridLayout()

# Create Encrypt Box
encryptBox = QGroupBox('Encrypt')
publicKeyLabel = QLabel('Public Key')
publicKey = QLineEdit()
encryptTextLabel = QLabel('Text to Encrypt')
encryptText = QTextEdit()
encryptButton = QPushButton('Click to Encrypt')
# Layout Encrypt Box
layoutEncrypt = QVBoxLayout()
layoutEncrypt.addWidget(publicKeyLabel)
layoutEncrypt.addWidget(publicKey)
layoutEncrypt.addSpacing(10)
layoutEncrypt.addWidget(encryptTextLabel)
layoutEncrypt.addWidget(encryptText)
layoutEncrypt.addSpacing(20)
layoutEncrypt.addWidget(encryptButton)
layoutEncrypt.addStretch(1)
encryptBox.setLayout(layoutEncrypt)

# Create Decrypt Box
decryptBox = QGroupBox('Decrypt')
privateKeyLabel = QLabel('Private Key')
privateKey = QLineEdit()
decryptTextLabel = QLabel('Text to Decrypt')
decryptText = QTextEdit()
decryptButton = QPushButton('Click to Decrypt')
# Layout Decrypt Box
layoutDecrypt = QVBoxLayout()
layoutDecrypt.addWidget(privateKeyLabel)
layoutDecrypt.addWidget(privateKey)
layoutDecrypt.addSpacing(10)
layoutDecrypt.addWidget(decryptTextLabel)
layoutDecrypt.addWidget(decryptText)
layoutDecrypt.addSpacing(20)
layoutDecrypt.addWidget(decryptButton)
layoutDecrypt.addStretch(1)
decryptBox.setLayout(layoutDecrypt)

# Create Result Box
resultBox = QGroupBox('Result')
resultLabel = QTextEdit()
# Layout Result Box
layoutResult = QVBoxLayout()
layoutResult.addWidget(resultLabel)
layoutResult.addStretch(1)
resultBox.setLayout(layoutResult)

# Layout Main Window
mainlayout.addWidget(encryptBox, 0, 0)
mainlayout.addWidget(decryptBox, 0, 1)
mainlayout.addWidget(resultBox, 1, 0, 1, 2)
mainlayout.setVerticalSpacing(30)
window.setLayout(mainlayout)

# # Action to Encrypt
# encryptButton.clicked.connect(self.clickEncrypt)
# def clickEncrypt(self):
#     self.resultLabel.setText(self.encryptText.text())

# # Action to Decrypt
# encryptButton.clicked.connect(self.clickDecrypt)
# def clickDecrypt(self):
#     self.resultLabel.setText(self.decryptText.text())

window.show()
app.exec()

# print('text to encrypt: ', encryptText.text())