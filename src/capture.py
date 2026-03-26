from scapy.all import sniff
from packet_parser import parse_packet
from packet_printer import print_packet

def handle_packet(packet):
    packet_info = parse_packet(packet)

    if packet_info is None:
        return

    print_packet(packet_info)


def start_capture(interface, count, protocol):
    print("Capture started")
    print(f"Interface: {interface}")
    print(f"Count: {count}")
    print(f"Protocol: {protocol}")

    sniff(
        iface=interface,
        prn=handle_packet,
        count=count if count > 0 else 0,
        filter=protocol if protocol else None,
        store=False,
    )