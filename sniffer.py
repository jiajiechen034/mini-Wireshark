from PyQt5.QtCore import QObject, pyqtSignal
from scapy.all import sniff
from packet_parser import parse_packet, PacketContext


class Sniffer(QObject):
    packet_ready = pyqtSignal(dict)
    capture_started = pyqtSignal()
    capture_finished = pyqtSignal()
    error_occurred = pyqtSignal(str)

    def __init__(self, interface=None, count=0, protocol=None):
        super().__init__()
        self.interface = interface or None
        self.count = count
        self.protocol = protocol or None
        self._running = True
        self.context = PacketContext()

    def stop_sniffing(self, packet):
        return not self._running

    def handle_packet(self, packet):
        packet_info = parse_packet(packet, self.context)
        if packet_info is not None:
            self.packet_ready.emit(packet_info)

    def run(self):
        try:
            self._running = True
            self.context.reset()
            self.capture_started.emit()

            sniff(
                iface=self.interface,
                prn=self.handle_packet,
                count=self.count if self.count > 0 else 0,
                filter=self.protocol if self.protocol else None,
                store=False,
                stop_filter=self.stop_sniffing,
            )
        except Exception as e:
            self.error_occurred.emit(str(e))
        finally:
            self.capture_finished.emit()

    def stop(self):
        self._running = False