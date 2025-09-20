from scapy.all import sniff, DNS, DNSQR, DNSRR, IP
from datetime import datetime


logfile = open("dns_log.txt", "a", encoding="utf-8")

def process_packet(packet):
    if packet.haslayer(DNS) and packet.getlayer(DNS).qd is not None:
        #  haslayer(DNS) = we are ensureing it’s a DNS packet.
        #.qd is not None = here we are ensureing it’s a query, not an empty DNS message.
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S") # we get the current timestamp in it
        src_ip = packet[IP].src # we extract the source IP address
        dst_ip = packet[IP].dst # we extract the destination IP address
                                #.dst = destination IP address
                                #.src = source IP address
        query_name = packet[DNSQR].qname.decode(errors="ignore")
            #.qname = the queried domain name ( its the domain name which w are visiting or the quiry adresing)
            #DNSQR = DNS Question Record.
            #Converting computer bytes into a human-readable string in here we are using decode() method
            #errors="ignore" = if there are any decoding errors, they will be ignored.
        log_line = f"[{timestamp}] {src_ip} -> {dst_ip} | Query: {query_name}"
        print(log_line)
        # we are printing the collected information to the console
        logfile.write(log_line + "\n")

        if packet.haslayer(DNSRR):
            for i in range(packet[DNS].ancount):
                answer = packet[DNS].an[i]
                if answer.type == 1: 
                    resp_line = f"    --> Response: {answer.rdata}"
                    print(resp_line)
                    logfile.write(resp_line + "\n")

        logfile.flush()# writing the log line to the file immediately

        #DNSRR = checking if response exists.
        #ancount = number of answers in DNS response have
        #an[i] = i-th answer record.
        #answer.type == 1 = type A (IPv4 address). we can use other types like AAAA for IPv6
        #Most common type (maps domain → IPv4) so we are using the IPv4.
        #rdata = returning the actual ip adress.

print("Starting DNS capture... Press CTRL+C to stop.\n")
sniff(filter="udp port 53", prn=process_packet, store=0)
#filter="udp port 53" = to only captureing DNS traffic
#prn = process_packet = callback for each packet
#store=0 =to avoide it from keeping packets in memory.