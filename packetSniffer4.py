import socket
import struct
import collections

# ANSI Color Codes for terminal formatting
GREEN = "\033[92m"
BLUE = "\033[94m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"
# DNS Cache dictionary to store previously resolved IPs (prevents duplicate DNS lag)
dns_cache = {}

def get_hostname(ip):
    """Performs reverse DNS lookup with caching to maximize speed."""
    if ip in dns_cache:
        return dns_cache[ip]
    
    try:
        # Attempt lookup and store result in cache
        hostname = socket.gethostbyaddr(ip)[0]
        dns_cache[ip] = hostname
        return hostname
    except (socket.herror, socket.gaierror, socket.timeout):
        # Cache failures too so it doesn't retry slow lookups for dead/unknown IPs
        dns_cache[ip] = "Unresolved"
        return "Unresolved"

def main():
    # Determine the local host IP to bind the raw socket
    host = socket.gethostbyname(socket.gethostname())
    print(f"{CYAN}Starting Fast DNS-Cached Windows Packet Sniffer on: {host}{RESET}")
    print("Listening for up to 100 packets with cached DNS lookups...\n" + "="*70)

    # Create a raw socket and bind it to the public interface (Requires Administrator privileges)
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    s.bind((host, 0))

    # Include IP headers in the capture
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # Enable promiscuous mode on Windows to capture network traffic
    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    packet_count = 0
    max_packets = 100
    
    # Tracking for the final statistics summary
    protocol_stats = collections.Counter()
    source_ip_stats = collections.Counter()

    try:
        while packet_count < max_packets:
            # Receive packets (65535 bytes buffer)
            raw_data, addr = s.recvfrom(65535)
            
            # Parse the IP header from the raw packet (First 20 bytes)
            ip_header = raw_data[0:20]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
            
            version_ihl = iph[0]
            ihl = version_ihl & 0xF
            iph_length = ihl * 4
            
            ttl = iph[5]
            protocol_num = iph[6]
            src_ip = socket.inet_ntoa(iph[8])
            dst_ip = socket.inet_ntoa(iph[9])

            # Initialize transport layer defaults
            src_port = "N/A"
            dst_port = "N/A"
            protocol = "Other"
            color = RESET

            # Map protocol number, assign color, and extract ports if applicable
            if protocol_num == 6:
                protocol = "TCP"
                color = GREEN
                if len(raw_data) >= iph_length + 4:
                    tcp_header = raw_data[iph_length:iph_length+4]
                    src_port, dst_port = struct.unpack('!HH', tcp_header)
            elif protocol_num == 17:
                protocol = "UDP"
                color = BLUE
                if len(raw_data) >= iph_length + 4:
                    udp_header = raw_data[iph_length:iph_length+4]
                    src_port, dst_port = struct.unpack('!HH', udp_header)
            elif protocol_num == 1:
                protocol = "ICMP"
                color = YELLOW

            packet_count += 1
            protocol_stats[protocol] += 1
            source_ip_stats[src_ip] += 1

            # Perform Cached Reverse DNS Lookups (Fast after the first lookup per IP)
            src_host = get_hostname(src_ip)
            dst_host = get_hostname(dst_ip)

            # Print clearly separated, color-coded packet blocks
            print(f"{color}--- Packet #{packet_count} of {max_packets} [{protocol}] ---{RESET}")
            print(f"  Source IP Address      : {src_ip} ({src_host})")
            print(f"  Source Port            : {src_port}")
            print(f"  Destination IP Address : {dst_ip} ({dst_host})")
            print(f"  Destination Port       : {dst_port}")
            print(f"  Protocol               : {protocol}")
            print(f"  TTL (Time To Live)     : {ttl}")
            print("-" * 50 + "\n")

    except KeyboardInterrupt:
        print(f"\n{YELLOW}Sniffer manually stopped by user.{RESET}")
    finally:
        # Turn off promiscuous mode before exiting
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        
        # Print Traffic Statistics Summary Report
        print("="*70)
        print(f"{CYAN}CAPTURE SUMMARY REPORT{RESET}")
        print(f"Total Packets Captured   : {packet_count}")
        
        print("\nProtocol Breakdown:")
        for proto, count in protocol_stats.items():
            print(f"  - {proto}: {count} packets")
            
        if source_ip_stats:
            most_active_ip, top_count = source_ip_stats.most_common(1)[0]
            print(f"\nMost Active Source IP    : {most_active_ip} ({top_count} packets sent)")
        print("="*70)

if __name__ == "__main__":
    main()