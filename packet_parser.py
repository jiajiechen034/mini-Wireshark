import time
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.layers.dns import DNS, DNSRR


class PacketContext:
    def __init__(self):
        self.packet_count = 0
        self.start_time = time.time()

    def reset(self):
        self.packet_count = 0
        self.start_time = time.time()

    def next_packet_info(self):
        self.packet_count += 1
        elapsed = time.time() - self.start_time
        timestamp = f"{elapsed:.3f}"
        return self.packet_count, timestamp

def parse_arp(packet, context):
    number, timestamp = context.next_packet_info()
    arp = packet[ARP]

    if arp.op == 1:
        info = f"Who has {arp.pdst}? Tell {arp.psrc}"
    elif arp.op == 2:
        info = f"{arp.psrc} is at {arp.hwsrc}"
    else:
        info = f"ARP op={arp.op}"

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
        "raw_packet": packet,
    }

def build_base_packet(packet, protocol, context):
    number, timestamp = context.next_packet_info()

    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
    elif packet.haslayer(IPv6):
        src = packet[IPv6].src
        dst = packet[IPv6].dst
    else:
        src = "?"
        dst = "?"

    return {
        "number": number,
        "time": timestamp,
        "protocol": protocol,
        "src": src,
        "sport": "-",
        "dst": dst,
        "dport": "-",
        "length": len(packet),
        "info": "",
        "raw_packet": packet,
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
    return ", ".join(mapping.get(ch, ch) for ch in flags_str)

def parse_tcp(packet, context):
    p = build_base_packet(packet, "TCP", context)

    tcp = packet[TCP]
    p["sport"] = tcp.sport
    p["dport"] = tcp.dport

    flags = decode_tcp_flags(tcp.sprintf("%TCP.flags%"))
    seq = tcp.seq
    ack = tcp.ack
    win = tcp.window
    payload_len = len(bytes(tcp.payload)) if tcp.payload else 0

    p["info"] = (
        f"{tcp.sport} → {tcp.dport} "
        f"[{flags}] "
        f"Seq={seq} Ack={ack} Win={win} Len={payload_len}"
    )

    return p

def decode_dns_type(qtype):
    mapping = {
        1: "A",
        2: "NS",
        5: "CNAME",
        6: "SOA",
        12: "PTR",
        15: "MX",
        16: "TXT",
        28: "AAAA",
        33: "SRV",
        65: "HTTPS",
    }
    return mapping.get(qtype, str(qtype))

def get_dns_answer_text(dns):
    if dns.ancount == 0 or dns.an is None:
        return ""

    answers = []

    try:
        answer = dns.an

        if isinstance(answer, DNSRR):
            while isinstance(answer, DNSRR):
                if hasattr(answer, "rdata"):
                    answers.append(str(answer.rdata))
                answer = answer.payload
        else:
            for a in answer:
                if hasattr(a, "rdata"):
                    answers.append(str(a.rdata))

    except Exception:
        pass

    return ", ".join(answers)

def parse_udp(packet, context):
    p = build_base_packet(packet, "UDP", context)
    udp = packet[UDP]
    p["sport"] = udp.sport
    p["dport"] = udp.dport

    if packet.haslayer(DNS):
        dns = packet[DNS]

        if dns.qd is not None:
            qname = dns.qd.qname
            if isinstance(qname, bytes):
                qname = qname.decode(errors="ignore")
            qname = qname.rstrip(".")

            qtype = decode_dns_type(dns.qd.qtype)

            if dns.qr == 0:
                p["info"] = f"Standard query {qtype} {qname}"
            else:
                answers = get_dns_answer_text(dns)
                if answers:
                    p["info"] = f"Standard query response {qtype} {qname} → {answers}"
                else:
                    p["info"] = f"Standard query response {qtype} {qname} (no answer)"
        else:
            if dns.qr == 0:
                p["info"] = "DNS Query"
            else:
                p["info"] = "DNS Response"

        return p

    p["info"] = f"{udp.sport} → {udp.dport} Len={udp.len}"
    return p

def decode_icmp(icmp_type, icmp_code):
    if icmp_type == 8 and icmp_code == 0:
        return "Echo Request"
    elif icmp_type == 0 and icmp_code == 0:
        return "Echo Reply"
    elif icmp_type == 3:
        code_map = {
            0: "Network Unreachable",
            1: "Host Unreachable",
            2: "Protocol Unreachable",
            3: "Port Unreachable",
        }
        reason = code_map.get(icmp_code, f"code={icmp_code}")
        return f"Destination Unreachable ({reason})"
    elif icmp_type == 11:
        return "Time Exceeded"
    else:
        return f"type={icmp_type} code={icmp_code}"

def parse_icmp(packet, context):
    p = build_base_packet(packet, "ICMP", context)
    icmp = packet[ICMP]

    info = decode_icmp(icmp.type, icmp.code)

    if icmp.type in (0, 8):
        icmp_id = getattr(icmp, "id", None)
        icmp_seq = getattr(icmp, "seq", None)

        if icmp_id is not None and icmp_seq is not None:
            info = f"{info} id=0x{icmp_id:04x} seq={icmp_seq}"

    p["info"] = info
    return p

def parse_packet(packet, context):
    if packet.haslayer(ARP):
        return parse_arp(packet, context)

    if not (packet.haslayer(IP) or packet.haslayer(IPv6)):
        return None

    if packet.haslayer(TCP):
        return parse_tcp(packet, context)
    elif packet.haslayer(UDP):
        return parse_udp(packet, context)
    elif packet.haslayer(ICMP):
        return parse_icmp(packet, context)

    return None