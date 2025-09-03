import sys
import os
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QTabWidget,
    QWidget, QLabel, QTextEdit, QLineEdit, QPushButton, QStatusBar, QFileDialog,
    QMessageBox, QSpinBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QPixmap, QFont
import asyncio
import socket
import dns.resolver
import whois
import requests
import psutil
import subprocess
import platform
import json
from urllib.parse import urlparse
import ssl
import ipaddress
from typing import Optional, List

# Custom thread for async operations
class NetworkWorker(QThread):
    result_signal = pyqtSignal(str)
    error_signal = pyqtSignal(str)

    def __init__(self, func, *args):
        super().__init__()
        self.func = func
        self.args = args

    def run(self):
        try:
            result = asyncio.run(self.func(*self.args))
            self.result_signal.emit(result)
        except Exception as e:
            self.error_signal.emit(str(e))

class KakaNetworkApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("KAKANETWORK - جعبه ابزار شبکه")
        self.setGeometry(100, 100, 1200, 800)
        self.font_size = 10  # Default font size for CLI outputs
        self.cli_widgets = []  # List to hold all CLI output QTextEdit widgets

        # Set up the UI
        self.setup_ui()
        self.apply_styles()

    def setup_ui(self):
        # Central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # Header
        header_widget = QWidget()
        header_layout = QVBoxLayout(header_widget)
        header_layout.setContentsMargins(10, 10, 10, 10)

        # Logo
        logo_label = QLabel()
        assets_path = os.path.join(os.path.dirname(__file__), "logo w.png")
        if os.path.exists(assets_path):
            pixmap = QPixmap(assets_path)
            if not pixmap.isNull():
                scaled_pixmap = pixmap.scaled(300, 300, Qt.AspectRatioMode.KeepAspectRatio)
                logo_label.setPixmap(scaled_pixmap)
            else:
                logo_label.setText("Logo not loaded")
        else:
            logo_label.setText("Logo file not found")
        logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header_layout.addWidget(logo_label)

        # Title
        title_label = QLabel("KAKANETWORK - جعبه ابزار شبکه")
        title_label.setFont(QFont("Arial", 20, QFont.Weight.Bold))
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header_layout.addWidget(title_label)

        # Center the header
        main_layout.addWidget(header_widget, alignment=Qt.AlignmentFlag.AlignCenter)

        main_layout.addWidget(header_widget)

        # Tab widget
        self.tab_widget = QTabWidget()
        self.tab_widget.setStyleSheet("""
            QTabBar::tab {
                background: #222222;
                color: #FFFFFF;
                padding: 10px 20px;
                border: 1px solid #808080;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background: #404040;
                color: #FFFFFF;
            }
        """)

        # Create tabs
        self.create_tabs()

        main_layout.addWidget(self.tab_widget)

        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("آماده برای شروع")

    def create_tabs(self):
        # Ping Tab
        self.ping_tab = self.create_ping_tab()
        self.tab_widget.addTab(self.ping_tab, "پینگ")

        # Port Scan Tab
        self.port_scan_tab = self.create_port_scan_tab()
        self.tab_widget.addTab(self.port_scan_tab, "اسکن پورت")

        # DNS Lookup Tab
        self.dns_tab = self.create_dns_tab()
        self.tab_widget.addTab(self.dns_tab, "جستجوی DNS")

        # WHOIS Tab
        self.whois_tab = self.create_whois_tab()
        self.tab_widget.addTab(self.whois_tab, "WHOIS دامنه")

        # Traceroute Tab
        self.traceroute_tab = self.create_traceroute_tab()
        self.tab_widget.addTab(self.traceroute_tab, "تریسرُت")

        # Reverse DNS Tab
        self.reverse_dns_tab = self.create_reverse_dns_tab()
        self.tab_widget.addTab(self.reverse_dns_tab, "Reverse DNS")

        # IP Geolocation Tab
        self.ip_geo_tab = self.create_ip_geo_tab()
        self.tab_widget.addTab(self.ip_geo_tab, "مکان‌یابی IP")

        # HTTP Headers Tab
        self.http_headers_tab = self.create_http_headers_tab()
        self.tab_widget.addTab(self.http_headers_tab, "هدرهای HTTP")

        # SSL Certificate Tab
        self.ssl_cert_tab = self.create_ssl_cert_tab()
        self.tab_widget.addTab(self.ssl_cert_tab, "گواهی SSL")

        # Subnet Calculator Tab
        self.subnet_calc_tab = self.create_subnet_calc_tab()
        self.tab_widget.addTab(self.subnet_calc_tab, "ماشین‌حساب Subnet")

        # Network Interfaces Tab
        self.network_interfaces_tab = self.create_network_interfaces_tab()
        self.tab_widget.addTab(self.network_interfaces_tab, "کارت‌های شبکه محلی")

        # Speed Test Tab
        self.speed_test_tab = self.create_speed_test_tab()
        self.tab_widget.addTab(self.speed_test_tab, "تست سرعت اینترنت")

        # Packet Capture Tab
        self.packet_capture_tab = self.create_packet_capture_tab()
        self.tab_widget.addTab(self.packet_capture_tab, "گرفتن بسته‌ها")

        # About Tab
        self.about_tab = self.create_about_tab()
        self.tab_widget.addTab(self.about_tab, "درباره")

        # Settings Tab
        self.settings_tab = self.create_settings_tab()
        self.tab_widget.addTab(self.settings_tab, "تنظیمات")

    def create_ping_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Input
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("آدرس:"), alignment=Qt.AlignmentFlag.AlignCenter)
        self.ping_input = QLineEdit()
        self.ping_input.setPlaceholderText("مثال: google.com یا 192.168.1.1")
        input_layout.addWidget(self.ping_input)

        ping_button = QPushButton("شروع پینگ")
        ping_button.clicked.connect(self.run_ping)
        input_layout.addWidget(ping_button)

        save_button = QPushButton("ذخیره خروجی")
        save_button.clicked.connect(lambda: self.save_output(self.ping_output, "ping_output.txt"))
        input_layout.addWidget(save_button)

        layout.addLayout(input_layout)

        # Output
        self.ping_output = QTextEdit()
        self.ping_output.setReadOnly(True)
        self.cli_widgets.append(self.ping_output)
        self.update_cli_font()
        layout.addWidget(self.ping_output)

        return widget

    def create_port_scan_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Input
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("آدرس:"), alignment=Qt.AlignmentFlag.AlignCenter)
        self.port_scan_input = QLineEdit()
        self.port_scan_input.setPlaceholderText("مثال: 192.168.1.1")
        input_layout.addWidget(self.port_scan_input)

        port_count_label = QLabel("تعداد پورت (1-1024):")
        input_layout.addWidget(port_count_label)
        self.port_count_input = QLineEdit("100")
        input_layout.addWidget(self.port_count_input)

        scan_button = QPushButton("شروع اسکن")
        scan_button.clicked.connect(self.run_port_scan)
        input_layout.addWidget(scan_button)

        save_button = QPushButton("ذخیره خروجی")
        save_button.clicked.connect(lambda: self.save_output(self.port_scan_output, "port_scan_output.txt"))
        input_layout.addWidget(save_button)

        layout.addLayout(input_layout)

        # Output
        self.port_scan_output = QTextEdit()
        self.port_scan_output.setReadOnly(True)
        self.cli_widgets.append(self.port_scan_output)
        layout.addWidget(self.port_scan_output)

        return widget

    def update_cli_font(self):
        font = QFont()
        font.setFamily("Courier New")
        font.setPointSize(self.font_size)
        for widget in self.cli_widgets:
            if hasattr(widget, 'setFont'):
                widget.setFont(font)

    def create_settings_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Font size setting
        font_layout = QHBoxLayout()
        font_layout.addWidget(QLabel("سایز فونت CLI:"))
        self.font_spinbox = QSpinBox()
        self.font_spinbox.setRange(8, 24)
        self.font_spinbox.setValue(self.font_size)
        self.font_spinbox.setSuffix(" پیکسل")
        font_layout.addWidget(self.font_spinbox)

        layout.addLayout(font_layout)

        # Apply button
        apply_button = QPushButton("اعمال تنظیمات")
        apply_button.clicked.connect(self.apply_settings)
        layout.addWidget(apply_button)

        # Spacer
        layout.addStretch()

        return widget

    def apply_settings(self):
        old_font_size = self.font_size
        self.font_size = self.font_spinbox.value()
        if old_font_size != self.font_size:
            self.update_cli_font()
        QMessageBox.information(self, "تنظیمات", "تنظیمات اعمال شد.")

    def create_dns_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Input
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("دامنه:"), alignment=Qt.AlignmentFlag.AlignCenter)
        self.dns_input = QLineEdit()
        self.dns_input.setPlaceholderText("مثال: google.com")
        input_layout.addWidget(self.dns_input)

        lookup_button = QPushButton("جستجو")
        lookup_button.clicked.connect(self.run_dns_lookup)
        input_layout.addWidget(lookup_button)

        save_button = QPushButton("ذخیره خروجی")
        save_button.clicked.connect(lambda: self.save_output(self.dns_output, "dns_output.txt"))
        input_layout.addWidget(save_button)

        layout.addLayout(input_layout)

        # Output
        self.dns_output = QTextEdit()
        self.dns_output.setReadOnly(True)
        self.cli_widgets.append(self.dns_output)
        layout.addWidget(self.dns_output)

        return widget

    def create_whois_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Input
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("دامنه:"), alignment=Qt.AlignmentFlag.AlignCenter)
        self.whois_input = QLineEdit()
        self.whois_input.setPlaceholderText("مثال: google.com")
        input_layout.addWidget(self.whois_input)

        whois_button = QPushButton("دریافت اطلاعات")
        whois_button.clicked.connect(self.run_whois)
        input_layout.addWidget(whois_button)

        save_button = QPushButton("ذخیره خروجی")
        save_button.clicked.connect(lambda: self.save_output(self.whois_output, "whois_output.txt"))
        input_layout.addWidget(save_button)

        layout.addLayout(input_layout)

        # Output
        self.whois_output = QTextEdit()
        self.whois_output.setReadOnly(True)
        self.cli_widgets.append(self.whois_output)
        layout.addWidget(self.whois_output)

        return widget

    def create_traceroute_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Input
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("آدرس:"), alignment=Qt.AlignmentFlag.AlignCenter)
        self.traceroute_input = QLineEdit()
        self.traceroute_input.setPlaceholderText("مثال: google.com یا 192.168.1.1")
        input_layout.addWidget(self.traceroute_input)

        trace_button = QPushButton("شروع تریک‌توان")
        trace_button.clicked.connect(self.run_traceroute)
        input_layout.addWidget(trace_button)

        save_button = QPushButton("ذخیره خروجی")
        save_button.clicked.connect(lambda: self.save_output(self.traceroute_output, "traceroute_output.txt"))
        input_layout.addWidget(save_button)

        layout.addLayout(input_layout)

        # Output
        self.traceroute_output = QTextEdit()
        self.traceroute_output.setReadOnly(True)
        self.cli_widgets.append(self.traceroute_output)
        layout.addWidget(self.traceroute_output)

        return widget

    def create_reverse_dns_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Input
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("آدرس IP:"), alignment=Qt.AlignmentFlag.AlignCenter)
        self.reverse_dns_input = QLineEdit()
        self.reverse_dns_input.setPlaceholderText("مثال: 8.8.8.8")
        input_layout.addWidget(self.reverse_dns_input)

        reverse_btn = QPushButton("جستجو")
        reverse_btn.clicked.connect(self.run_reverse_dns)
        input_layout.addWidget(reverse_btn)

        save_button = QPushButton("ذخیره خروجی")
        save_button.clicked.connect(lambda: self.save_output(self.reverse_dns_output, "reverse_dns_output.txt"))
        input_layout.addWidget(save_button)

        layout.addLayout(input_layout)

        # Output
        self.reverse_dns_output = QTextEdit()
        self.reverse_dns_output.setReadOnly(True)
        layout.addWidget(self.reverse_dns_output)

        return widget

    def create_ip_geo_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Input
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("آدرس IP:"), alignment=Qt.AlignmentFlag.AlignCenter)
        self.ip_geo_input = QLineEdit()
        self.ip_geo_input.setPlaceholderText("مثال: 8.8.8.8")
        input_layout.addWidget(self.ip_geo_input)

        geo_button = QPushButton("مکان‌یابی")
        geo_button.clicked.connect(self.run_ip_geolocation)
        input_layout.addWidget(geo_button)

        save_button = QPushButton("ذخیره خروجی")
        save_button.clicked.connect(lambda: self.save_output(self.ip_geo_output, "ip_geo_output.txt"))
        input_layout.addWidget(save_button)

        layout.addLayout(input_layout)

        # Output
        self.ip_geo_output = QTextEdit()
        self.ip_geo_output.setReadOnly(True)
        layout.addWidget(self.ip_geo_output)

        return widget

    def create_http_headers_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Input
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("آدرس وب:"), alignment=Qt.AlignmentFlag.AlignCenter)
        self.http_headers_input = QLineEdit()
        self.http_headers_input.setPlaceholderText("مثال: https://google.com")
        input_layout.addWidget(self.http_headers_input)

        headers_button = QPushButton("دریافت هدرها")
        headers_button.clicked.connect(self.run_http_headers)
        input_layout.addWidget(headers_button)

        save_button = QPushButton("ذخیره خروجی")
        save_button.clicked.connect(lambda: self.save_output(self.http_headers_output, "http_headers_output.txt"))
        input_layout.addWidget(save_button)

        layout.addLayout(input_layout)

        # Output
        self.http_headers_output = QTextEdit()
        self.http_headers_output.setReadOnly(True)
        layout.addWidget(self.http_headers_output)

        return widget

    def create_ssl_cert_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Input
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("دامنه:"), alignment=Qt.AlignmentFlag.AlignCenter)
        self.ssl_cert_input = QLineEdit()
        self.ssl_cert_input.setPlaceholderText("مثال: google.com")
        input_layout.addWidget(self.ssl_cert_input)

        cert_button = QPushButton("دریافت گواهی")
        cert_button.clicked.connect(self.run_ssl_cert)
        input_layout.addWidget(cert_button)

        save_button = QPushButton("ذخیره خروجی")
        save_button.clicked.connect(lambda: self.save_output(self.ssl_cert_output, "ssl_cert_output.txt"))
        input_layout.addWidget(save_button)

        layout.addLayout(input_layout)

        # Output
        self.ssl_cert_output = QTextEdit()
        self.ssl_cert_output.setReadOnly(True)
        layout.addWidget(self.ssl_cert_output)

        return widget

    def create_subnet_calc_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Input
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("CIDR:"), alignment=Qt.AlignmentFlag.AlignCenter)
        self.subnet_input = QLineEdit()
        self.subnet_input.setPlaceholderText("مثال: 192.168.1.0/24")
        input_layout.addWidget(self.subnet_input)

        calc_button = QPushButton("محاسبه")
        calc_button.clicked.connect(self.run_subnet_calc)
        input_layout.addWidget(calc_button)

        save_button = QPushButton("ذخیره خروجی")
        save_button.clicked.connect(lambda: self.save_output(self.subnet_output, "subnet_calc_output.txt"))
        input_layout.addWidget(save_button)

        layout.addLayout(input_layout)

        # Output
        self.subnet_output = QTextEdit()
        self.subnet_output.setReadOnly(True)
        layout.addWidget(self.subnet_output)

        return widget

    def create_network_interfaces_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Input (no input needed for network interfaces)
        button_layout = QHBoxLayout()

        interfaces_button = QPushButton("دریافت اطلاعات")
        interfaces_button.clicked.connect(self.run_network_interfaces)
        button_layout.addWidget(interfaces_button)

        save_button = QPushButton("ذخیره خروجی")
        save_button.clicked.connect(lambda: self.save_output(self.network_interfaces_output, "network_interfaces_output.txt"))
        button_layout.addWidget(save_button)

        layout.addLayout(button_layout)

        # Output
        self.network_interfaces_output = QTextEdit()
        self.network_interfaces_output.setReadOnly(True)
        layout.addWidget(self.network_interfaces_output)

        return widget

    def create_speed_test_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Input (no input needed for speed test)
        button_layout = QHBoxLayout()

        speed_button = QPushButton("شروع تست")
        speed_button.clicked.connect(self.run_speed_test)
        button_layout.addWidget(speed_button)

        save_button = QPushButton("ذخیره خروجی")
        save_button.clicked.connect(lambda: self.save_output(self.speed_test_output, "speed_test_output.txt"))
        button_layout.addWidget(save_button)

        layout.addLayout(button_layout)

        # Output
        self.speed_test_output = QTextEdit()
        self.speed_test_output.setReadOnly(True)
        layout.addWidget(self.speed_test_output)

        return widget

    def create_packet_capture_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Input
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("اینترفیس:"), alignment=Qt.AlignmentFlag.AlignCenter)
        self.packet_interface_input = QLineEdit()
        self.packet_interface_input.setPlaceholderText("مثال: eth0 یا \\Device\\NPF_{...}")
        input_layout.addWidget(self.packet_interface_input)

        packet_count_label = QLabel("تعداد بسته:")
        input_layout.addWidget(packet_count_label)
        self.packet_count_input = QLineEdit("10")
        input_layout.addWidget(self.packet_count_input)

        capture_button = QPushButton("شروع گرفتن")
        capture_button.clicked.connect(self.run_packet_capture)
        input_layout.addWidget(capture_button)

        save_button = QPushButton("ذخیره خروجی")
        save_button.clicked.connect(lambda: self.save_output(self.packet_capture_output, "packet_capture_output.txt"))
        input_layout.addWidget(save_button)

        layout.addLayout(input_layout)

        # Output
        self.packet_capture_output = QTextEdit()
        self.packet_capture_output.setReadOnly(True)
        layout.addWidget(self.packet_capture_output)

        return widget

    def create_about_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Logo
        assets_path = os.path.join(os.path.dirname(__file__), "logo w.png")
        if os.path.exists(assets_path):
            logo_label = QLabel()
            pixmap = QPixmap(assets_path)
            if not pixmap.isNull():
                scaled_pixmap = pixmap.scaled(200, 200, Qt.AspectRatioMode.KeepAspectRatio)
                logo_label.setPixmap(scaled_pixmap)
            else:
                logo_label.setText("Logo not loaded")
        else:
            logo_label.setText("Logo file not found")
        logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(logo_label)

        about_text = QTextEdit()
        about_text.setReadOnly(True)
        about_text.setText("""
این نرم‌افزار توسط KAKANETWORK ساخته شده است.
از این ابزار تنها در شبکه‌های مجاز و برای اهداف قانونی استفاده کنید.

ویژگی‌ها:
• پینگ کردن آدرس‌های شبکه
• اسکن پورت‌های TCP
• جستجوی DNS
• اطلاعات WHOIS دامنه‌ها
• ردیابی مسیر (Traceroute)
• Reverse DNS
• مکان‌یابی IP
• هدرهای HTTP
• اطلاعات گواهی SSL
• ماشین‌حساب Subnet
• کارت‌های شبکه محلی
• تست سرعت اینترنت
• گرفتن بسته‌های شبکه
        """)
        layout.addWidget(about_text)

        return widget

    # Placeholder methods for now
    def run_ping(self):
        host = self.ping_input.text().strip()
        if not host:
            QMessageBox.warning(self, "خطا", "لطفاً آدرس را وارد کنید.")
            return
        self.status_bar.showMessage("در حال اجرای پینگ...")
        self.ping_output.clear()
        self.ping_output.setText("شروع پینگ " + host + "...\n")

        async def ping_func():
            try:
                if platform.system().lower() == "windows":
                    cmd = ["ping", "-n", "4", host]
                else:
                    cmd = ["ping", "-c", "4", host]

                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                return result.stdout
            except Exception as e:
                return f"خطا در اجرای پینگ: {str(e)}"

        self.ping_worker = NetworkWorker(ping_func)
        self.ping_worker.result_signal.connect(lambda result: self.ping_output.setText(self.ping_output.toPlainText() + result + "\nپینگ تکمیل شد."))
        self.ping_worker.error_signal.connect(lambda e: self.ping_output.setText(self.ping_output.toPlainText() + f"خطا: {e}\n"))
        self.ping_worker.start()

    def run_port_scan(self):
        host = self.port_scan_input.text().strip()
        port_count = int(self.port_count_input.text() or "100")
        if not host:
            QMessageBox.warning(self, "خطا", "لطفاً آدرس را وارد کنید.")
            return
        self.status_bar.showMessage("در حال اسکن پورت‌ها...")
        self.port_scan_output.clear()

        async def port_scan_func():
            open_ports = []
            try:
                for port in range(1, min(port_count + 1, 1025)):
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((host, port))
                    if result == 0:
                        open_ports.append(port)
                    sock.close()

                if open_ports:
                    return f"پورت‌های باز: {', '.join(map(str, open_ports))}"
                else:
                    return "هیچ پورت باز یافت نشد."
            except Exception as e:
                return f"خطا در اسکن پورت: {str(e)}"

        self.port_scan_worker = NetworkWorker(port_scan_func)
        self.port_scan_worker.result_signal.connect(self.port_scan_output.setText)
        self.port_scan_worker.result_signal.connect(lambda: self.status_bar.showMessage("اسکن پورت تکمیل شد"))
        self.port_scan_worker.error_signal.connect(lambda e: self.status_bar.showMessage(f"خطا: {e}"))
        self.port_scan_worker.start()

    def run_dns_lookup(self):
        domain = self.dns_input.text().strip()
        if not domain:
            QMessageBox.warning(self, "خطا", "لطفاً دامنه را وارد کنید.")
            return
        self.status_bar.showMessage("در حال جستجوی DNS...")
        self.dns_output.clear()

        async def dns_lookup_func():
            try:
                resolver = dns.resolver.Resolver()
                info = {}

                # A records
                try:
                    a_records = resolver.resolve(domain, 'A')
                    info['رکوردهای A'] = '\n'.join([r.to_text() for r in a_records])
                except:
                    info['رکوردهای A'] = "یافت نشد"

                # AAAA records
                try:
                    aaaa_records = resolver.resolve(domain, 'AAAA')
                    info['رکوردهای AAAA'] = '\n'.join([r.to_text() for r in aaaa_records])
                except:
                    info['رکوردهای AAAA'] = "یافت نشد"

                # MX records
                try:
                    mx_records = resolver.resolve(domain, 'MX')
                    info['رکوردهای MX'] = '\n'.join([f"{r.preference} {r.exchange}" for r in mx_records])
                except:
                    info['رکوردهای MX'] = "یافت نشد"

                # TXT records
                try:
                    txt_records = resolver.resolve(domain, 'TXT')
                    info['رکوردهای TXT'] = '\n'.join([r.to_text() for r in txt_records])
                except:
                    info['رکوردهای TXT'] = "یافت نشد"

                output = ""
                for key, value in info.items():
                    output += f"{key}:\n{value}\n\n"
                return output
            except Exception as e:
                return f"خطا در جستجوی DNS: {str(e)}"

        self.dns_worker = NetworkWorker(dns_lookup_func)
        self.dns_worker.result_signal.connect(self.dns_output.setText)
        self.dns_worker.result_signal.connect(lambda: self.status_bar.showMessage("جستجوی DNS تکمیل شد"))
        self.dns_worker.error_signal.connect(lambda e: self.status_bar.showMessage(f"خطا: {e}"))
        self.dns_worker.start()

    def run_whois(self):
        domain = self.whois_input.text().strip()
        if not domain:
            QMessageBox.warning(self, "خطا", "لطفاً دامنه را وارد کنید.")
            return
        self.status_bar.showMessage("در حال دریافت اطلاعات WHOIS...")
        self.whois_output.clear()

        async def whois_func():
            try:
                w = whois.whois(domain)
                info = []
                for key, value in w.items():
                    if value:
                        info.append(f"{key}: {value}")
                return "\n".join(info)
            except Exception as e:
                return f"خطا در دریافت WHOIS: {str(e)}"

        self.whois_worker = NetworkWorker(whois_func)
        self.whois_worker.result_signal.connect(self.whois_output.setText)
        self.whois_worker.result_signal.connect(lambda: self.status_bar.showMessage("WHOIS تکمیل شد"))
        self.whois_worker.error_signal.connect(lambda e: self.status_bar.showMessage(f"خطا: {e}"))
        self.whois_worker.start()

    def run_traceroute(self):
        host = self.traceroute_input.text().strip()
        if not host:
            QMessageBox.warning(self, "خطا", "لطفاً آدرس را وارد کنید.")
            return
        self.status_bar.showMessage("در حال اجرای traceroute...")
        self.traceroute_output.clear()

        async def traceroute_func():
            try:
                if platform.system().lower() == "windows":
                    cmd = ["tracert", host]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                    return result.stdout
                else:
                    cmd = ["traceroute", host]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                    return result.stdout
            except subprocess.TimeoutExpired:
                return "مدت زمان اجرای فرمان منقضی شد."
            except Exception as e:
                return f"خطا در اجرای traceroute: {str(e)}"

        self.traceroute_worker = NetworkWorker(traceroute_func)
        self.traceroute_worker.result_signal.connect(self.traceroute_output.setText)
        self.traceroute_worker.result_signal.connect(lambda: self.status_bar.showMessage("Traceroute تکمیل شد"))
        self.traceroute_worker.error_signal.connect(lambda e: self.status_bar.showMessage(f"خطا: {e}"))
        self.traceroute_worker.start()

    def run_reverse_dns(self):
        ip = self.reverse_dns_input.text().strip()
        if not ip:
            QMessageBox.warning(self, "خطا", "لطفاً آدرس IP را وارد کنید.")
            return
        self.status_bar.showMessage("در حال اجرای Reverse DNS...")
        self.reverse_dns_output.clear()

        async def reverse_dns_func():
            try:
                result = socket.gethostbyaddr(ip)
                return f"نام دامنه: {result[0]}\n\nآدرس‌های IP:\n" + '\n'.join(result[2])
            except socket.herror as e:
                return f"خطا در Reverse DNS: {str(e)}"

        self.reverse_dns_worker = NetworkWorker(reverse_dns_func)
        self.reverse_dns_worker.result_signal.connect(self.reverse_dns_output.setText)
        self.reverse_dns_worker.result_signal.connect(lambda: self.status_bar.showMessage("Reverse DNS تکمیل شد"))
        self.reverse_dns_worker.error_signal.connect(lambda e: self.status_bar.showMessage(f"خطا: {e}"))
        self.reverse_dns_worker.start()

    def run_ip_geolocation(self):
        ip = self.ip_geo_input.text().strip()
        if not ip:
            QMessageBox.warning(self, "خطا", "لطفاً آدرس IP را وارد کنید.")
            return
        self.status_bar.showMessage("در حال مکان‌یابی IP...")
        self.ip_geo_output.clear()

        async def ip_geo_func():
            try:
                response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    result = f"کشور: {data.get('country', 'N/A')}\n"
                    result += f"منطقه: {data.get('regionName', 'N/A')}\n"
                    result += f"شهر: {data.get('city', 'N/A')}\n"
                    result += f"کد پستی: {data.get('zip', 'N/A')}\n"
                    result += f"مختصات: {data.get('lat', 'N/A')}, {data.get('lon', 'N/A')}\n"
                    result += f"ارائه‌دهنده: {data.get('isp', 'N/A')}\n"
                    result += f"سازمان: {data.get('org', 'N/A')}"
                    return result
                else:
                    return "خطا در دریافت اطلاعات مکانی."
            except Exception as e:
                return f"خطا در مکان‌یابی IP: {str(e)}"

        self.ip_geo_worker = NetworkWorker(ip_geo_func)
        self.ip_geo_worker.result_signal.connect(self.ip_geo_output.setText)
        self.ip_geo_worker.result_signal.connect(lambda: self.status_bar.showMessage("مکان‌یابی IP تکمیل شد"))
        self.ip_geo_worker.error_signal.connect(lambda e: self.status_bar.showMessage(f"خطا: {e}"))
        self.ip_geo_worker.start()

    def run_http_headers(self):
        url = self.http_headers_input.text().strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        if not url:
            QMessageBox.warning(self, "خطا", "لطفاً آدرس وب را وارد کنید.")
            return
        self.status_bar.showMessage("در حال دریافت هدرهای HTTP...")
        self.http_headers_output.clear()

        async def http_headers_func():
            try:
                response = requests.head(url, timeout=30)
                headers = response.headers
                result = ""
                for key, value in headers.items():
                    result += f"{key}: {value}\n"
                return result
            except Exception as e:
                return f"خطا در دریافت هدرها: {str(e)}"

        self.http_headers_worker = NetworkWorker(http_headers_func)
        self.http_headers_worker.result_signal.connect(self.http_headers_output.setText)
        self.http_headers_worker.result_signal.connect(lambda: self.status_bar.showMessage("هدرهای HTTP دریافت شد"))
        self.http_headers_worker.error_signal.connect(lambda e: self.status_bar.showMessage(f"خطا: {e}"))
        self.http_headers_worker.start()

    def run_ssl_cert(self):
        domain = self.ssl_cert_input.text().strip()
        if not domain:
            QMessageBox.warning(self, "خطا", "لطفاً دامنه را وارد کنید.")
            return
        self.status_bar.showMessage("در حال دریافت گواهی SSL...")
        self.ssl_cert_output.clear()

        async def ssl_cert_func():
            try:
                context = ssl.create_default_context()
                conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
                conn.connect((domain, 443))
                cert = conn.getpeercert()
                conn.close()

                result = f"موضوع: {cert.get('subject', 'N/A')}\n"
                result += f"صادرکننده: {cert.get('issuer', 'N/A')}\n"
                result += f"تاریخ شروع اعتبار: {cert.get('notBefore', 'N/A')}\n"
                result += f"تاریخ پایان اعتبار: {cert.get('notAfter', 'N/A')}\n"
                return result
            except Exception as e:
                return f"خطا در دریافت گواهی SSL: {str(e)}"

        self.ssl_cert_worker = NetworkWorker(ssl_cert_func)
        self.ssl_cert_worker.result_signal.connect(self.ssl_cert_output.setText)
        self.ssl_cert_worker.result_signal.connect(lambda: self.status_bar.showMessage("گواهی SSL دریافت شد"))
        self.ssl_cert_worker.error_signal.connect(lambda e: self.status_bar.showMessage(f"خطا: {e}"))
        self.ssl_cert_worker.start()

    def run_subnet_calc(self):
        cidr = self.subnet_input.text().strip()
        if not cidr:
            QMessageBox.warning(self, "خطا", "لطفاً CIDR را وارد کنید.")
            return
        self.status_bar.showMessage("در حال محاسبه subnet...")
        self.subnet_output.clear()

        async def subnet_calc_func():
            try:
                network = ipaddress.ip_network(cidr, strict=False)
                result = f"شبکه: {network.network_address}\n"
                result += f"ماسک: {network.netmask}\n"
                result += f"broadcast: {network.broadcast_address if network.version == 4 else 'N/A'}\n"
                result += f"رنج IP: {network[0]} - {network[-1]}\n"
                result += f"تعداد هاست قابل اختصاص: {network.num_addresses - 2 if network.num_addresses > 2 else network.num_addresses}\n"
                return result
            except Exception as e:
                return f"خطا در محاسبه subnet: {str(e)}"

        self.subnet_calc_worker = NetworkWorker(subnet_calc_func)
        self.subnet_calc_worker.result_signal.connect(self.subnet_output.setText)
        self.subnet_calc_worker.result_signal.connect(lambda: self.status_bar.showMessage("محاسبه subnet تکمیل شد"))
        self.subnet_calc_worker.error_signal.connect(lambda e: self.status_bar.showMessage(f"خطا: {e}"))
        self.subnet_calc_worker.start()

    def run_network_interfaces(self):
        self.status_bar.showMessage("در حال دریافت اطلاعات کارت‌های شبکه...")
        self.network_interfaces_output.clear()

        async def network_interfaces_func():
            try:
                result = ""
                for interface, addrs in psutil.net_if_addrs().items():
                    result += f"اینترفیس: {interface}\n"
                    for addr in addrs:
                        if addr.family == socket.AF_INET:
                            result += f"  IPv4: {addr.address}\n"
                            result += f"  MASk: {addr.netmask}\n"
                        elif addr.family == socket.AF_INET6:
                            result += f"  IPv6: {addr.address}\n"
                        elif addr.family == socket.AF_PACKET:
                            result += f"  MAC: {addr.address}\n"
                    result += "\n"
                return result or "هیچ اینترفیسی یافت نشد."
            except Exception as e:
                return f"خطا در دریافت اطلاعات: {str(e)}"

        self.network_interfaces_worker = NetworkWorker(network_interfaces_func)
        self.network_interfaces_worker.result_signal.connect(self.network_interfaces_output.setText)
        self.network_interfaces_worker.result_signal.connect(lambda: self.status_bar.showMessage("اطلاعات کارت‌های شبکه دریافت شد"))
        self.network_interfaces_worker.error_signal.connect(lambda e: self.status_bar.showMessage(f"خطا: {e}"))
        self.network_interfaces_worker.start()

    def run_speed_test(self):
        self.status_bar.showMessage("در حال اجرای تست سرعت...")
        self.speed_test_output.clear()

        async def speed_test_func():
            try:
                import speedtest
                st = speedtest.Speedtest()
                st.get_best_server()

                download_speed = st.download() / 1000000  # Mbps
                upload_speed = st.upload() / 1000000      # Mbps

                result = f"سرعت دانلود: {download_speed:.2f} Mbps\n"
                result += f"سرعت آپلود: {upload_speed:.2f} Mbps\n"
                result += f"پینگ: {st.results.ping:.2f} ms"
                return result
            except ImportError:
                return "مدول speedtest نصب نشده است. لطفاً با pip install speedtest-cli نصب کنید."
            except Exception as e:
                return f"خطا در تست سرعت: {str(e)}"

        self.speed_test_worker = NetworkWorker(speed_test_func)
        self.speed_test_worker.result_signal.connect(self.speed_test_output.setText)
        self.speed_test_worker.result_signal.connect(lambda: self.status_bar.showMessage("تست سرعت تکمیل شد"))
        self.speed_test_worker.error_signal.connect(lambda e: self.status_bar.showMessage(f"خطا: {e}"))
        self.speed_test_worker.start()

    def run_packet_capture(self):
        interface = self.packet_interface_input.text().strip()
        count = int(self.packet_count_input.text() or "10")
        if not interface:
            QMessageBox.warning(self, "خطا", "لطفاً اینترفیس را وارد کنید.")
            return
        warning = QMessageBox.question(self, "هشدار", "این عملیات نیازمند دسترسی ادمین و نصب scapy است. ادامه می‌دهید؟", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if warning == QMessageBox.StandardButton.No:
            return
        self.status_bar.showMessage("در حال گرفتن بسته‌ها...")
        self.packet_capture_output.clear()

        async def packet_capture_func():
            try:
                from scapy.all import sniff, get_if_list
                packets = sniff(iface=interface, count=count)
                result = ""
                for i, pkt in enumerate(packets):
                    result += f"بسته {i+1}:\n{pkt.show()}\n\n"
                return result
            except ImportError:
                return "مدول scapy نصب نشده است. لطفاً با pip install scapy نصب کنید."
            except Exception as e:
                return f"خطا در گرفتن بسته‌ها: {str(e)}"

        self.packet_capture_worker = NetworkWorker(packet_capture_func)
        self.packet_capture_worker.result_signal.connect(self.packet_capture_output.setText)
        self.packet_capture_worker.result_signal.connect(lambda: self.status_bar.showMessage("گرفتن بسته‌ها تکمیل شد"))
        self.packet_capture_worker.error_signal.connect(lambda e: self.status_bar.showMessage(f"خطا: {e}"))
        self.packet_capture_worker.start()

    def save_output(self, output_widget, default_name):
        content = output_widget.toPlainText()
        if not content.strip():
            QMessageBox.warning(self, "خطا", "محتوایی برای ذخیره وجود ندارد.")
            return
        file_name, _ = QFileDialog.getSaveFileName(self, "ذخیره خروجی", default_name, "Text Files (*.txt);;All Files (*)")
        if file_name:
            try:
                with open(file_name, 'w', encoding='utf-8') as f:
                    f.write(content)
                QMessageBox.information(self, "موفقیت", f"خروجی در {file_name} ذخیره شد.")
            except Exception as e:
                QMessageBox.critical(self, "خطا", f"خطا در ذخیره فایل: {str(e)}")

    def apply_styles(self):
        self.setStyleSheet("""
            QMainWindow {
                background-color: #000000;
                color: #FFFFFF;
                font-family: Tahoma, Arial;
            }
            QLabel {
                color: #FFFFFF;
                font-size: 12px;
            }
            QLineEdit {
                background-color: #222222;
                color: #FFFFFF;
                border: 1px solid #808080;
                padding: 5px;
                font-size: 12px;
            }
            QPushButton {
                background-color: #222222;
                color: #FFFFFF;
                border: 1px solid #808080;
                padding: 10px 15px;
                font-size: 12px;
                min-width: 80px;
            }
            QPushButton:hover {
                background-color: #404040;
                color: #FFFFFF;
                font-weight: bold;
            }
            QPushButton:pressed {
                background-color: #606060;
                color: #FFFFFF;
            }
            QTextEdit {
                background-color: #111111;
                color: #FFFFFF;
                border: 1px solid #808080;
                font-family: 'Courier New', monospace;
                font-size: 10px;
                padding: 5px;
            }
            QStatusBar {
                background-color: #222222;
                color: #FFFFFF;
                border-top: 1px solid #808080;
            }
            QTabWidget::pane {
                border: 1px solid #808080;
            }
            QWidget {
                background-color: #000000;
            }
        """)

def main():
    app = QApplication(sys.argv)
    window = KakaNetworkApp()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()