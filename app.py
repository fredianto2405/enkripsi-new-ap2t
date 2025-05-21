import sys
import socket
import psutil
import getpass
import platform
import json
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton,
    QVBoxLayout, QHBoxLayout, QGroupBox, QGraphicsDropShadowEffect
)
from PyQt5.QtGui import QFont, QColor
from PyQt5.QtCore import Qt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from base64 import b64encode


class ModernUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Enkripsi New AP2T")
        self.setFixedSize(400, 350)
        self.setStyleSheet("background-color: #f9f9f9; font-family: 'Segoe UI';")
        self.init_ui()
    
    def get_ip_address(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "Unavailable"

    def get_wifi_mac(self):
        for interface_name, addresses in psutil.net_if_addrs().items():
          if "wlan" in interface_name.lower() or "wi-fi" in interface_name.lower():
            for addr in addresses:
              if addr.family == psutil.AF_LINK:
                return interface_name, addr.address
        return None, None
    
    def encrypt(self, key, iv, plaintext):
      padder = padding.PKCS7(128).padder()
      padded_data = padder.update(plaintext.encode()) + padder.finalize()
      cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
      encryptor = cipher.encryptor()
      ciphertext = encryptor.update(padded_data) + encryptor.finalize()
      return b64encode(ciphertext).decode()
    
    def copy_to_clipboard(self):
      key = b'ThisIsMySecretKey123456789012312'
      iv = b'My16ByteInitVect'

      iface, mac = self.get_wifi_mac()
      mac_info = {
        "interface": iface,
        "mac_address": mac
      }

      os_info = {
        "os_name": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "platform": platform.platform(),
        "architecture": platform.machine()
      }

      data = {
        "ip_address": self.get_ip_address(),
        "mac_info": mac_info,
        "hostname": socket.gethostname(),
        "username": getpass.getuser(),
        "os_info": os_info
      }

      json_data = json.dumps(data)
      ciphertext = self.encrypt(key, iv, json_data)

      clipboard = QApplication.clipboard()
      clipboard.setText(ciphertext)

    def init_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)

        # Group Box
        info_group = QGroupBox("Informasi")
        info_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #dcdcdc;
                border-radius: 8px;
                margin-top: 10px;
                padding: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 3px 0 3px;
            }
        """)
        info_layout = QVBoxLayout()
        info_layout.setContentsMargins(15, 15, 15, 15)
        info_layout.setSpacing(12)

        # IP Address
        ip_layout = QHBoxLayout()
        ip_label = QLabel("IP Address")
        ip_label.setFont(QFont("Segoe UI", 10))
        ip_label.setFixedWidth(120)
        ip_input = QLineEdit(self.get_ip_address())
        ip_input.setReadOnly(True)
        ip_input.setStyleSheet("background: #ffffff; padding: 6px; border-radius: 6px; border: 1px solid #ccc;")
        ip_layout.addWidget(ip_label)
        ip_layout.addWidget(ip_input)
        info_layout.addLayout(ip_layout)

        # MAC Address
        iface, mac = self.get_wifi_mac()
        mac_layout = QHBoxLayout()
        mac_label = QLabel("MAC Address")
        mac_label.setFont(QFont("Segoe UI", 10))
        mac_label.setFixedWidth(120)
        mac_input = QLineEdit(mac)
        mac_input.setReadOnly(True)
        mac_input.setStyleSheet("background: #ffffff; padding: 6px; border-radius: 6px; border: 1px solid #ccc;")
        mac_layout.addWidget(mac_label)
        mac_layout.addWidget(mac_input)
        info_layout.addLayout(mac_layout)

        # User
        user_layout = QHBoxLayout()
        user_label = QLabel("Username")
        user_label.setFont(QFont("Segoe UI", 10))
        user_label.setFixedWidth(120)
        user_input = QLineEdit(getpass.getuser())
        user_input.setReadOnly(True)
        user_input.setStyleSheet("background: #ffffff; padding: 6px; border-radius: 6px; border: 1px solid #ccc;")
        user_layout.addWidget(user_label)
        user_layout.addWidget(user_input)
        info_layout.addLayout(user_layout)

        # Operating System
        os_name = platform.system() + " " + platform.release()
        os_layout = QHBoxLayout()
        os_label = QLabel("OS")
        os_label.setFont(QFont("Segoe UI", 10))
        os_label.setFixedWidth(120)
        os_input = QLineEdit(os_name)
        os_input.setReadOnly(True)
        os_input.setStyleSheet("background: #ffffff; padding: 6px; border-radius: 6px; border: 1px solid #ccc;")
        os_layout.addWidget(os_label)
        os_layout.addWidget(os_input)
        info_layout.addLayout(os_layout)

        info_group.setLayout(info_layout)
        main_layout.addWidget(info_group)

        # Info Label
        info_label = QLabel("* Informasi tersebut akan dikirim ke sistem untuk keamanan")
        info_label.setStyleSheet("color: #555; font-size: 11px; margin-top: 5px;")
        info_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(info_label)

        # Modern Button
        self.button = QPushButton("Copy to Clipboard")
        self.button.setCursor(Qt.PointingHandCursor)
        self.button.setFixedHeight(40)
        self.button.setFixedWidth(240)
        self.button.setStyleSheet("""
            QPushButton {
                background-color: #2d89ef;
                color: white;
                border: none;
                border-radius: 10px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #1e70bf;
            }
            QPushButton:pressed {
                background-color: #165ba8;
                padding-left: 2px;
                padding-top: 2px;
            }
        """)
        self.button.clicked.connect(self.copy_to_clipboard)

        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(15)
        shadow.setOffset(0, 2)
        shadow.setColor(QColor(0, 0, 0, 50))
        self.button.setGraphicsEffect(shadow)

        main_layout.addWidget(self.button, alignment=Qt.AlignCenter)

        self.setLayout(main_layout)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    ui = ModernUI()
    ui.show()
    sys.exit(app.exec_())
