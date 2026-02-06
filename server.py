#!/usr/bin/env python3
"""
DNS Server for covert communication - AWS Ready Version
Receives data encoded in DNS queries and responds with encoded data in DNS responses
"""

import socket
import struct
import threading
from datetime import datetime
import sys


class DNSServer:
    def __init__(self, host='0.0.0.0', port=5353, domain='covert.local'):
        """
        Initialize DNS server
        
        Args:
            host: IP address to bind to
            port: Port to listen on (use 5353 for non-root, 53 requires root)
            domain: Domain name to respond to
        """
        self.host = host
        self.port = port
        self.domain = domain.lower()
        self.sock = None
        self.running = False
        self.packet_count = 0
        
    def start(self):
        """Start the DNS server"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Bind to all interfaces
            self.sock.bind((self.host, self.port))
            self.running = True
            
            print("=" * 70)
            print(f"[*] DNS Server STARTED successfully")
            print(f"[*] Listening on: {self.host}:{self.port}")
            print(f"[*] Domain: {self.domain}")
            print(f"[*] Server is ready to receive DNS queries")
            print("=" * 70)
            print()
            
            # Get local IP for reference
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                s.close()
                print(f"[i] Local IP address: {local_ip}")
            except:
                pass
            
            print(f"[i] Configure your client to use: <YOUR_AWS_IP>:{self.port}")
            print(f"[i] Make sure AWS Security Group allows UDP port {self.port}")
            print(f"[i] Press Ctrl+C to stop")
            print()
            
            while self.running:
                try:
                    data, addr = self.sock.recvfrom(4096)  # Increased buffer size
                    self.packet_count += 1
                    
                    print(f"[{self.packet_count}] ====== NEW PACKET RECEIVED ======")
                    print(f"    From: {addr[0]}:{addr[1]}")
                    print(f"    Size: {len(data)} bytes")
                    
                    # Handle each request in a separate thread
                    thread = threading.Thread(target=self.handle_request, args=(data, addr))
                    thread.daemon = True
                    thread.start()
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"[!] Error receiving packet: {e}")
                    
        except PermissionError:
            print(f"[!] Permission denied! Port {self.port} requires root privileges.")
            print(f"[!] Try using port 5353 or run with: sudo python3 {sys.argv[0]}")
            sys.exit(1)
        except OSError as e:
            print(f"[!] Cannot bind to {self.host}:{self.port}")
            print(f"[!] Error: {e}")
            print(f"[!] Make sure the port is not already in use")
            sys.exit(1)
        except KeyboardInterrupt:
            print("\n[*] Shutting down server...")
        finally:
            self.stop()
    
    def stop(self):
        """Stop the DNS server"""
        self.running = False
        if self.sock:
            self.sock.close()
        print(f"[*] Server stopped. Total packets received: {self.packet_count}")
    
    def handle_request(self, data, addr):
        """Handle incoming DNS request"""
        try:
            # Show raw data for debugging
            print(f"    Raw (hex): {data[:50].hex()}{'...' if len(data) > 50 else ''}")
            
            # Parse DNS query
            query_info = self.parse_dns_query(data)
            
            if query_info:
                query_name = query_info['name']
                query_type = query_info['type']
                query_type_name = self.get_query_type_name(query_type)
                
                print(f"    Query Type: {query_type_name} ({query_type})")
                print(f"    Domain: {query_name}")
                
                # Extract covert data from subdomain
                covert_data = self.extract_covert_data(query_name)
                
                if covert_data:
                    print(f"    >>> DECODED MESSAGE: '{covert_data}'")
                else:
                    print(f"    (No covert data - regular DNS query)")
                
                # Create and send DNS response
                response = self.create_dns_response(data, query_info)
                self.sock.sendto(response, addr)
                print(f"    Response sent: {len(response)} bytes")
            else:
                print(f"    [!] Failed to parse DNS query")
                
            print()
                
        except Exception as e:
            print(f"    [!] Error handling request: {e}")
            import traceback
            traceback.print_exc()
            print()
    
    def get_query_type_name(self, qtype):
        """Get human-readable query type name"""
        types = {
            1: 'A',
            2: 'NS',
            5: 'CNAME',
            6: 'SOA',
            12: 'PTR',
            15: 'MX',
            16: 'TXT',
            28: 'AAAA',
            255: 'ANY'
        }
        return types.get(qtype, 'UNKNOWN')
    
    def parse_dns_query(self, data):
        """Parse DNS query packet"""
        try:
            if len(data) < 12:
                return None
            
            # DNS header is 12 bytes
            transaction_id = struct.unpack('!H', data[0:2])[0]
            flags = struct.unpack('!H', data[2:4])[0]
            qdcount = struct.unpack('!H', data[4:6])[0]
            
            # Check if this is a query (QR bit = 0)
            if flags & 0x8000:
                return None
            
            # Parse question section
            pos = 12
            domain_parts = []
            
            while pos < len(data):
                length = data[pos]
                if length == 0:
                    pos += 1
                    break
                if length > 63:  # Might be a pointer
                    if length >= 192:  # Compression pointer
                        break
                    return None
                
                pos += 1
                if pos + length > len(data):
                    return None
                    
                label = data[pos:pos+length].decode('utf-8', errors='ignore')
                domain_parts.append(label)
                pos += length
            
            if pos + 4 > len(data):
                return None
                
            query_type = struct.unpack('!H', data[pos:pos+2])[0]
            query_class = struct.unpack('!H', data[pos+2:pos+4])[0]
            
            return {
                'transaction_id': transaction_id,
                'name': '.'.join(domain_parts),
                'type': query_type,
                'class': query_class,
                'raw_query': data
            }
        except Exception as e:
            print(f"    [!] Parse error: {e}")
            return None
    
    def extract_covert_data(self, query_name):
        """Extract covert data from DNS query name"""
        # Data is encoded in subdomain before our domain
        # Format: <encoded_data>.<domain>
        
        if not query_name.lower().endswith(self.domain):
            return None
        
        # Remove our domain suffix
        subdomain = query_name[:-(len(self.domain) + 1)]
        
        if not subdomain:
            return None
        
        # Decode hex-encoded data
        try:
            # Remove any dots (they're just separators for DNS labels)
            hex_data = subdomain.replace('.', '')
            decoded = bytes.fromhex(hex_data).decode('utf-8')
            return decoded
        except:
            return subdomain  # Return as-is if not hex-encoded
    
    def create_dns_response(self, query_data, query_info):
        """Create DNS response packet"""
        transaction_id = query_info['transaction_id']
        
        # DNS Header
        response = struct.pack('!H', transaction_id)
        
        # Flags: Response, Authoritative Answer, No error
        flags = 0x8580
        response += struct.pack('!H', flags)
        
        # Questions: 1, Answers: 1, Authority: 0, Additional: 0
        response += struct.pack('!H', 1)  # QDCOUNT
        response += struct.pack('!H', 1)  # ANCOUNT
        response += struct.pack('!H', 0)  # NSCOUNT
        response += struct.pack('!H', 0)  # ARCOUNT
        
        # Question section (copy from query)
        question_start = 12
        pos = question_start
        while pos < len(query_data) and query_data[pos] != 0:
            if query_data[pos] >= 192:  # Compression pointer
                pos += 2
                break
            pos += query_data[pos] + 1
        else:
            pos += 1
        pos += 4  # type + class
        
        response += query_data[question_start:pos]
        
        # Answer section
        # Name (pointer to question)
        response += b'\xc0\x0c'
        
        # Type A (1), Class IN (1)
        response += struct.pack('!H', 1)  # Type A
        response += struct.pack('!H', 1)  # Class IN
        
        # TTL (4 bytes) - 60 seconds
        response += struct.pack('!I', 60)
        
        # Data length (2 bytes) - 4 bytes for IPv4
        response += struct.pack('!H', 4)
        
        # IP Address - 127.0.0.1 as confirmation
        response += socket.inet_aton('127.0.0.1')
        
        return response


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='DNS Covert Channel Server')
    parser.add_argument('-p', '--port', type=int, default=5353,
                        help='Port to listen on (default: 5353)')
    parser.add_argument('-d', '--domain', type=str, default='covert.local',
                        help='Domain to respond to (default: covert.local)')
    parser.add_argument('--host', type=str, default='0.0.0.0',
                        help='IP to bind to (default: 0.0.0.0)')
    
    args = parser.parse_args()
    
    # Create and start DNS server
    server = DNSServer(host=args.host, port=args.port, domain=args.domain)
    server.start()


if __name__ == '__main__':
    main()