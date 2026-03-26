header_printed = False

def print_header():
    print(
        f"{'No':<5} {'Time':<8} {'Proto':<6} {'Source':<18} "
        f"{'Sport':<7} {'Destination':<18} {'Dport':<7} {'Length':<8} {'Info'}"
    )

def print_packet(packet_info):
    global header_printed

    if not header_printed:
        print_header()
        header_printed = True

    print(
        f"{packet_info['number']:<5} "
        f"{packet_info['time']:<8} "
        f"{packet_info['protocol']:<6} "
        f"{packet_info['src']:<18} "
        f"{str(packet_info['sport']):<7} "
        f"{packet_info['dst']:<18} "
        f"{str(packet_info['dport']):<7} "
        f"{packet_info['length']:<8} "
        f"{packet_info['info']}"
    )