import socket

# Define the proxy server's address and port
proxy_host = 'proxy.example.com'
proxy_port = 1234

# Define the data to send
data = b'Hello, world!'

# Create a socket object for IPv4 and raw packets
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

# Connect the socket to the proxy server
s.connect((proxy_host, proxy_port))

# Send the data through the socket
s.send(data)

# Close the socket
s.close()

import socket
import struct

# The IP address and port of the receiver application
receiver_address = ('127.0.0.1', 4444)

# Create a raw IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

# Set the IP header fields
ip_version = 4  # IPv4
ip_header_length = 5  # 5 * 4 = 20 bytes
ip_tos = 0  # default
ip_total_length = 0  # will be filled in later
ip_id = 0  # default
ip_flags = 0  # don't fragment
ip_fragment_offset = 0  # first fragment
ip_ttl = 64  # default
ip_protocol = socket.IPPROTO_TCP  # TCP protocol
ip_checksum = 0  # will be filled in later
ip_source_address = socket.inet_aton('127.0.0.1')  # the sender's IP address
ip_dest_address = socket.inet_aton(receiver_address[0])  # the receiver's IP address

# Construct the IP header
ip_header = struct.pack('!BBHHHBBH4s4s', (ip_version << 4) | ip_header_length, ip_tos,
                        ip_total_length, ip_id, (ip_flags << 13) | ip_fragment_offset,
                        ip_ttl, ip_protocol, ip_checksum, ip_source_address, ip_dest_address)

# The data to send
http_data = b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'

# Send the packet
sock.sendto(ip_header + http_data, receiver_address)
