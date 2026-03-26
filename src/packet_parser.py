import time
import socket
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP
from scapy.layers.dns import DNS

packet_count = 0
start_time = time.time()

def next_packet_info():
    global packet_count
    packet_count += 1

    elapsed = time.time() - start_time
    timestamp = f"{elapsed:.3f}"

    return packet_count, timestamp

def parse_arp(packet):
    number, timestamp = next_packet_info()
    arp = packet[ARP]

    info = ""
    if arp.op == 1:
        info = "Who has?"
    elif arp.op == 2:
        info = f"Is at {arp.hwsrc}"
    else:
        info = f"op={arp.op}"

    return {
        "number": number,
        "time": timestamp,
        "protocol": "ARP",
        "src": arp.psrc,
        "sport": "-",
        "dst": arp.pdst,
        "dport": "-",
        "length": len(packet),
        "info": info,
    }

def build_base_packet(packet, protocol):
    number, timestamp = next_packet_info()

    return {
        "number": number,
        "time": timestamp,
        "protocol": protocol,
        "src": packet[IP].src,
        "sport": "-",
        "dst": packet[IP].dst,
        "dport": "-",
        "length": len(packet),
        "info": "",
    }

def decode_tcp_flags(flags_str):
    mapping = {
        "S": "SYN",
        "A": "ACK",
        "F": "FIN",
        "R": "RST",
        "P": "PSH",
        "U": "URG",
    }
    return "-".join(mapping.get(ch, ch) for ch in flags_str)

def get_service_name(port, protocol): 
    try: 
        return socket.getservbyport(port, protocol)
    except:
        return None
    
def parse_tcp(packet):
    p = build_base_packet(packet, "TCP")

    tcp = packet[TCP]
    p["sport"] = tcp.sport
    p["dport"] = tcp.dport

    service = get_service_name(tcp.dport, "tcp")

    flags = decode_tcp_flags(tcp.sprintf("%TCP.flags%"))
    if service:
        p["info"] = f"{service.upper()} {flags}"
    else:
        p["info"] = flags
    return p

def parse_udp(packet):
    p = build_base_packet(packet, "UDP")
    udp = packet[UDP]
    p["sport"] = udp.sport
    p["dport"] = udp.dport

    if packet.haslayer(DNS):
        dns = packet[DNS]
        if dns.qr == 0:
            p["info"] = "DNS Query"
        else:
            p["info"] = "DNS Response"
        return p
    
    service = get_service_name(udp.dport, "udp")
    if service:
        p["info"] = service.upper()
    else:
        p["info"] = f"Len={udp.len}"
    return p

def decode_icmp(icmp_type, icmp_code):
    if icmp_type == 8 and icmp_code == 0:
        return "Echo Request"
    elif icmp_type == 0 and icmp_code == 0:
        return "Echo Reply"
    elif icmp_type == 3:
        return "Destination Unreachable"
    else:
        return f"type={icmp_type} code={icmp_code}"
    
def parse_icmp(packet):
    p = build_base_packet(packet, "ICMP")
    icmp = packet[ICMP]
    p["info"] = decode_icmp(icmp.type, icmp.code)
    return p

def parse_packet(packet):
    if packet.haslayer(ARP):
        return parse_arp(packet)
    
    if not packet.haslayer(IP):
        return None

    if packet.haslayer(TCP):
        return parse_tcp(packet)
    elif packet.haslayer(UDP):
        return parse_udp(packet)
    elif packet.haslayer(ICMP):
        return parse_icmp(packet)

    return None