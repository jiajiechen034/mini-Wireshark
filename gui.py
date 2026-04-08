import sys
import csv
from PyQt5.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QLineEdit,
    QLabel,
    QComboBox,
    QTableWidget,
    QTableWidgetItem,
    QAbstractItemView,
    QFileDialog,
    QMessageBox,
    QHeaderView,
    QTextEdit
)
from PyQt5.QtCore import QThread, QTimer
from sniffer import Sniffer


class GUIWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.thread = None
        self.sniffer = None

        self.setWindowTitle("Mini-Wireshark")
        self.resize(1200, 650)

        self.packets = []
        self.pending_packets = []
        self.filtered_packets = []

        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.flush_pending_packets)
        self.update_timer.start(20)

        central = QWidget()
        self.setCentralWidget(central)

        main_layout = QVBoxLayout()
        controls_layout = QHBoxLayout()

        self.interface_input = QLineEdit()
        self.interface_input.setPlaceholderText("Interface, e.g. en0 or eth0")

        self.protocol_box = QComboBox()
        self.protocol_box.addItems(["", "tcp", "udp", "icmp", "arp"])

        self.capture_filter_input = QLineEdit()
        self.capture_filter_input.setPlaceholderText("Capture filter, e.g. udp port 53")

        self.display_filter_input = QLineEdit()
        self.display_filter_input.setPlaceholderText("Search displayed packets")

        self.start_button = QPushButton("Start")
        self.stop_button = QPushButton("Stop")
        self.save_button = QPushButton("Save")
        self.apply_filter_button = QPushButton("Apply Filter")

        controls_layout.addWidget(QLabel("Interface:"))
        controls_layout.addWidget(self.interface_input)

        controls_layout.addWidget(QLabel("Protocol:"))
        controls_layout.addWidget(self.protocol_box)

        controls_layout.addWidget(QLabel("Capture:"))
        controls_layout.addWidget(self.capture_filter_input)

        controls_layout.addWidget(self.start_button)
        controls_layout.addWidget(self.stop_button)
        controls_layout.addWidget(self.save_button)

        controls_layout.addWidget(QLabel("Search:"))
        controls_layout.addWidget(self.display_filter_input)
        controls_layout.addWidget(self.apply_filter_button)

        self.table = QTableWidget(0, 9)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)

        self.table.setHorizontalHeaderLabels([
            "No",
            "Time",
            "Proto",
            "Source",
            "Source Port",
            "Destination",
            "Destination Port",
            "Length",
            "Info",
        ])

        self.table.setColumnWidth(0, 60)
        self.table.setColumnWidth(1, 90)
        self.table.setColumnWidth(2, 70)
        self.table.setColumnWidth(3, 150)
        self.table.setColumnWidth(4, 100)
        self.table.setColumnWidth(5, 150)
        self.table.setColumnWidth(6, 120)
        self.table.setColumnWidth(7, 80)
        self.table.setColumnWidth(8, 350)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(8, QHeaderView.Stretch)

        self.detail_box = QTextEdit()
        self.detail_box.setReadOnly(True)
        self.detail_box.setPlaceholderText("Select a packet to see details...")

        main_layout.addLayout(controls_layout)
        main_layout.addWidget(self.table)
        main_layout.addWidget(self.detail_box)
        central.setLayout(main_layout)

        self.table.cellClicked.connect(self.on_row_clicked)

        self.stop_button.setEnabled(False)
        self.save_button.setEnabled(False)

        self.start_button.clicked.connect(self.on_start_clicked)
        self.stop_button.clicked.connect(self.on_stop_clicked)
        self.save_button.clicked.connect(self.on_save_clicked)
        self.apply_filter_button.clicked.connect(self.on_filter_clicked)

    def on_start_clicked(self):
        self.table.setRowCount(0)
        self.packets.clear()
        self.pending_packets.clear()
        self.filtered_packets.clear()

        interface = self.interface_input.text().strip()
        protocol = self.protocol_box.currentText().strip()
        capture_filter = self.capture_filter_input.text().strip()

        sniff_filter = capture_filter if capture_filter else protocol

        self.thread = QThread()
        self.sniffer = Sniffer(
            interface=interface if interface else None,
            protocol=sniff_filter if sniff_filter else None,
        )
        self.sniffer.moveToThread(self.thread)

        self.thread.started.connect(self.sniffer.run)
        self.sniffer.packet_ready.connect(self.add_packet_row)
        self.sniffer.capture_started.connect(self.capture_started)
        self.sniffer.capture_finished.connect(self.capture_finished)
        self.sniffer.error_occurred.connect(self.capture_error)

        self.sniffer.capture_finished.connect(self.thread.quit)
        self.thread.finished.connect(self.sniffer.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.finished.connect(self.on_thread_finished)

        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.save_button.setEnabled(False)

        self.thread.start()

    def on_stop_clicked(self):
        if self.sniffer is not None:
            self.stop_button.setEnabled(False)
            self.sniffer.stop()

    def on_save_clicked(self):
        packets_to_save = self.filtered_packets if self.filtered_packets else self.packets

        if not packets_to_save:
            QMessageBox.information(self, "No Data", "There are no packets to save.")
            return

        path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Capture",
            "capture.csv",
            "CSV Files (*.csv)"
        )

        if not path:
            return

        try:
            with open(path, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "No",
                    "Time",
                    "Proto",
                    "Source",
                    "Source Port",
                    "Destination",
                    "Destination Port",
                    "Length",
                    "Info",
                ])

                for packet in packets_to_save:
                    writer.writerow([
                        packet["number"],
                        packet["time"],
                        packet["protocol"],
                        packet["src"],
                        packet["sport"],
                        packet["dst"],
                        packet["dport"],
                        packet["length"],
                        packet["info"],
                    ])

            QMessageBox.information(self, "Saved", f"Capture saved to:\n{path}")

        except Exception as e:
            QMessageBox.critical(self, "Save Error", str(e))

    def on_filter_clicked(self):
        text = self.display_filter_input.text().strip().lower()

        if not text:
            self.filtered_packets = []
            self.refresh_table(self.packets)
            return

        result = []
        for packet in self.packets:
            if (
                text in str(packet["protocol"]).lower()
                or text in str(packet["src"]).lower()
                or text in str(packet["dst"]).lower()
                or text in str(packet["sport"]).lower()
                or text in str(packet["dport"]).lower()
                or text in str(packet["info"]).lower()
            ):
                result.append(packet)

        self.filtered_packets = result
        self.refresh_table(result)
    
    def on_row_clicked(self, row, column):
        if self.filtered_packets:
            packet = self.filtered_packets[row]
        else:
            packet = self.packets[row]

        self.detail_box.setText(self.format_packet_details(packet))
    
    def format_packet_details(self, packet):
        lines = []

        lines.append(f"Frame {packet['number']}")
        lines.append(f"Time: {packet['time']} s")
        lines.append(f"Protocol: {packet['protocol']}")
        lines.append("")

        lines.append("=== Network ===")
        lines.append(f"Source: {packet['src']}")
        lines.append(f"Destination: {packet['dst']}")
        lines.append("")

        lines.append("=== Transport ===")
        lines.append(f"Source Port: {packet['sport']}")
        lines.append(f"Destination Port: {packet['dport']}")
        lines.append(f"Length: {packet['length']}")
        lines.append("")

        lines.append("=== Info ===")
        lines.append(packet["info"])

        return "\n".join(lines)

    def capture_started(self):
        print("Capture started")

    def capture_finished(self):
        print("Capture finished")

    def capture_error(self, message):
        print("Capture error:", message)
        QMessageBox.critical(self, "Capture Error", message)
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    def add_packet_row(self, packet_info):
        self.packets.append(packet_info)

        search_text = self.display_filter_input.text().strip().lower()
        if search_text:
            if (
                search_text in str(packet_info["protocol"]).lower()
                or search_text in str(packet_info["src"]).lower()
                or search_text in str(packet_info["dst"]).lower()
                or search_text in str(packet_info["sport"]).lower()
                or search_text in str(packet_info["dport"]).lower()
                or search_text in str(packet_info["info"]).lower()
            ):
                self.filtered_packets.append(packet_info)
                self.pending_packets.append(packet_info)
        else:
            self.pending_packets.append(packet_info)

    def on_thread_finished(self):
        print("Thread finished")
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.save_button.setEnabled(True)
        self.thread = None
        self.sniffer = None

    def flush_pending_packets(self):
        if not self.pending_packets:
            return

        packets_to_add = self.pending_packets
        self.pending_packets = []

        for packet_info in packets_to_add:
            row = self.table.rowCount()
            self.table.insertRow(row)

            values = [
                packet_info["number"],
                packet_info["time"],
                packet_info["protocol"],
                packet_info["src"],
                packet_info["sport"],
                packet_info["dst"],
                packet_info["dport"],
                packet_info["length"],
                packet_info["info"],
            ]

            for col, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                item.setToolTip(str(value))
                self.table.setItem(row, col, item)

        self.table.viewport().update()

    def refresh_table(self, packets):
        self.table.setRowCount(0)

        for packet_info in packets:
            row = self.table.rowCount()
            self.table.insertRow(row)

            values = [
                packet_info["number"],
                packet_info["time"],
                packet_info["protocol"],
                packet_info["src"],
                packet_info["sport"],
                packet_info["dst"],
                packet_info["dport"],
                packet_info["length"],
                packet_info["info"],
            ]

            for col, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                item.setToolTip(str(value))
                self.table.setItem(row, col, item)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = GUIWindow()
    window.show()
    sys.exit(app.exec_())