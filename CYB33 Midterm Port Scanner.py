import socket
import argparse
import time
from datetime import datetime

ALLOWED_HOSTS = ["127.0.0.1", "localhost", "scanme.nmap.org"]

def scan_port(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)

        result = sock.connect_ex((host, port))
        sock.close()

        if result == 0:
            print(f"[OPEN] Port {port}")
        else:
            print(f"[CLOSED] Port {port}")
    except Exception as e:
        print(f"Error scanning port {port} on {host}: {e}")

def main():
    parser = argparse.ArgumentParser(description="Simple Port Scanner")
    parser.add_argument("host", help="Target host to scan")
    parser.add_argument("start_port", type=int, help="Starting port number")
    parser.add_argument("end_port", type=int, help="Ending port number")
    args = parser.parse_args()

    if args.host not in ALLOWED_HOSTS:
        print(f"ERROR: Scanning host '{args.host}' is not allowed.")
        return
    if args.start_port < 0 or args.start_port > 65535:
        print("ERROR: Invalid starting port.")
        return
    if args.end_port < 0 or args.end_port > 65535:
        print("ERROR: Invalid ending port.")
        return
    if args.start_port > args.end_port:
        print("ERROR: Starting port cannot be greater than ending port.")
        return
    print(f"\nScan started: {datetime.now()}")
    print(f"Scanning host: {args.host}")
    print(f"Port range: {args.start_port} to {args.end_port}\n")
    for port in range(args.start_port, args.end_port + 1):
        scan_port(args.host, port)
        time.sleep(0.2)  # Slight delay to avoid overwhelming the target

    print(f"\nScan completed: {datetime.now()}")

if __name__ == "__main__":
    main()