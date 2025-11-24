"""Live DNS capture — renamed from `dns_logger.py`.

This script captures DNS packets and appends rows to `dns_log.csv`.
"""

# Original content from dns_logger.py — only filename and docstring updated.
from scapy.all import sniff, DNS, DNSQR, DNSRR, IP, get_if_list, get_if_addr, conf
import re
from datetime import datetime
import logging
import csv
import os
import socket
import sys

# -------------------------
# Basic setup
# -------------------------
CSV_PATH = "dns_log.csv"   # Name of the output CSV file
# Capture only DNS packets on either UDP or TCP port 53. Note: this
# will not capture DNS-over-HTTPS (DoH) traffic which is carried over
# HTTPS (port 443) and does not include a DNS layer. To capture DoH
# you'd need to intercept HTTPS (e.g. a proxy) or capture at the DNS
# resolver/gateway.
PCAP_FILTER = "port 53"

# -------------------------
# Hide Scapy's warning messages
# -------------------------
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# -------------------------
# Find which network interface to use
# -------------------------
def get_local_ip_via_socket():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return None

def pick_interface_by_local_ip():
    local_ip = get_local_ip_via_socket()
    if not local_ip:
        return None

    interfaces = get_if_list()
    for iface in interfaces:
        try:
            addr = get_if_addr(iface)
        except Exception:
            addr = None
        if addr == local_ip:
            return iface
    return None


def normalize_iface_name(raw: str) -> str:
    """Normalize various Windows interface identifiers into the form
    scapy/winpcap expects (e.g. `\\Device\\NPF_{GUID}`) when possible.

    If `raw` is already a device path, return it unchanged. If it's a
    bare GUID like `{GUID}` return `\\Device\\NPF_{GUID}`. Otherwise
    return the original string.
    """
    if not raw:
        return raw
    raw = str(raw)
    # Already looks like a device path
    if raw.startswith("\\Device\\NPF_") or raw.startswith("/"):
        return raw
    # GUID-like: {xxxxxxxx-xxxx-...}
    m = re.match(r"^\{?[0-9A-Fa-f-]{36}\}?$", raw)
    if m:
        guid = raw.strip('{}')
        return f"\\Device\\NPF_{{{guid}}}"
    return raw

def ensure_csv_has_header(path):
    header = ["timestamp", "is_response", "src_ip", "dst_ip", "qname", "qtype", "ans_count", "response_ips"]
    file_exists = os.path.isfile(path)
    if not file_exists or os.path.getsize(path) == 0:
        with open(path, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(header)

def append_row_to_csv(path, rowdict):
    ensure_csv_has_header(path)
    with open(path, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            rowdict.get("timestamp", ""),
            rowdict.get("is_response", ""),
            rowdict.get("src_ip", ""),
            rowdict.get("dst_ip", ""),
            rowdict.get("qname", ""),
            rowdict.get("qtype", ""),
            rowdict.get("ans_count", ""),
            rowdict.get("response_ips", "")
        ])

def extract_answers(packet_dns):
    answers = []
    try:
        ancount = packet_dns.ancount
        for i in range(ancount):
            try:
                ans = packet_dns.an[i]
                if getattr(ans, "type", None) == 1:
                    ips = getattr(ans, "rdata", None)
                    if ips is not None:
                        answers.append(str(ips))
            except Exception:
                continue
    except Exception:
        pass
    return answers

def process_packet(packet):
    if not packet.haslayer(IP):
        return
    if not packet.haslayer(DNS):
        return

    dns = packet.getlayer(DNS)
    qname = ""
    qtype = ""

    if dns.qd is not None and dns.qdcount > 0:
        try:
            qname = dns.qd.qname.decode(errors="ignore") if isinstance(dns.qd.qname, bytes) else str(dns.qd.qname)
        except Exception:
            qname = str(dns.qd.qname)
        try:
            qtype = str(dns.qd.qtype)
        except Exception:
            qtype = ""

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    is_response = bool(dns.qr)

    answers = extract_answers(dns)
    ans_count = dns.ancount if hasattr(dns, "ancount") else 0
    response_ips = ";".join(answers) if answers else ""

    if is_response:
        print(f"[{timestamp}] {src_ip} -> {dst_ip} | RESPONSE: {qname} answers={response_ips}")
    else:
        print(f"[{timestamp}] {src_ip} -> {dst_ip} | QUERY: {qname}")

    row = {
        "timestamp": timestamp,
        "is_response": int(is_response),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "qname": qname,
        "qtype": qtype,
        "ans_count": ans_count,
        "response_ips": response_ips
    }
    try:
        append_row_to_csv(CSV_PATH, row)
    except Exception as e:
        print("Failed to write CSV row:", e, file=sys.stderr)


def packet_is_dns_like(packet):
    """Return True for packets that are DNS or appear to be DNS (port 53).

    This helps capture DNS carried over TCP as well as UDP. It will not
    match DNS-over-HTTPS (DoH) because those packets don't carry a DNS
    layer and use port 443.
    """
    try:
        if packet.haslayer(DNS):
            return True
        # Check UDP/TCP port fields if present
        if packet.haslayer('UDP'):
            udp = packet.getlayer('UDP')
            return getattr(udp, 'sport', None) == 53 or getattr(udp, 'dport', None) == 53
        if packet.haslayer('TCP'):
            tcp = packet.getlayer('TCP')
            return getattr(tcp, 'sport', None) == 53 or getattr(tcp, 'dport', None) == 53
    except Exception:
        return False
    return False

def main():
    print("capture.py starting...")
    iface = pick_interface_by_local_ip()
    if iface:
        print(f"Auto-selected interface: {iface}")
    else:
        interfaces = get_if_list()
        print("Could not auto-detect active interface. Choose one:")
        for i, it in enumerate(interfaces):
            try:
                addr = get_if_addr(it)
            except Exception:
                addr = ""
            # Show the interface identifier and any detected IP address to help selection
            print(f"{i}: {it}  (addr={addr})")
        try:
            choice = int(input("Enter interface number: ").strip())
            selected = interfaces[choice]
            iface = normalize_iface_name(selected)
        except Exception:
            print("Invalid selection. Exiting.")
            return

    print("Writing DNS logs to:", os.path.abspath(CSV_PATH))
    ensure_csv_has_header(CSV_PATH)
    print("Starting sniffing (press CTRL+C to stop)...\n")

    try:
        # Try to open the chosen interface. If scapy fails with the first
        # form, try a normalized device path (Windows WinPcap naming).
        try:
            sniff(
                filter=PCAP_FILTER,
                prn=process_packet,
                store=0,
                lfilter=lambda p: p.haslayer(IP) and packet_is_dns_like(p),
                iface=iface,
                promisc=True,
            )
        except Exception:
            alt = normalize_iface_name(iface)
            if alt == iface:
                raise
            sniff(
                filter=PCAP_FILTER,
                prn=process_packet,
                store=0,
                lfilter=lambda p: p.haslayer(IP) and packet_is_dns_like(p),
                iface=alt,
                promisc=True,
            )
    except KeyboardInterrupt:
        print("\nStopped by user (CTRL+C). Exiting.")
    except Exception as e:
        print("Sniffer error:", e, file=sys.stderr)

if __name__ == "__main__":
    main()
