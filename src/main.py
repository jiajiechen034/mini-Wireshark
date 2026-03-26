import argparse
from capture import start_capture

def build_parser():
    parser = argparse.ArgumentParser(prog="wireshark")
    parser.add_argument("--interface")
    parser.add_argument("--count", type=int, default=0,)
    parser.add_argument("--protocol", choices=["tcp", "udp", "icmp", "arp"])
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    print("WireShark starting...")
    start_capture(interface=args.interface, count=args.count, protocol=args.protocol)

if __name__ == "__main__":
    main()