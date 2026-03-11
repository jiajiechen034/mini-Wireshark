from scapy.all import sniff

def handle_packet(packet):
    print(packet.summary())

def start_capture(interface, count, protocol):
    print("Capture started")
    print(f"Interface: {interface}")
    print(f"Count: {count}")
    print(f"Protocol: {protocol}")

    sniff(
        iface=interface,
        prn=handle_packet,
        count=count if count > 0 else 0,
    )