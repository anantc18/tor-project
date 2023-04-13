import socket, struct
import binascii

#  --------------------------- ETH Header ---------------------------

# Unpack Ethernet Header
def unpack_eth_hdr(eth_hdr):
    # Length of ethernet header is 14 bytes
    eth_hdr = struct.unpack("!6s6sH", eth_hdr)
    
    eth_hdr_info = {}
    eth_hdr_info["dst_mac"] = binascii.hexlify(eth_hdr[0]).decode()
    eth_hdr_info["src_mac"] = binascii.hexlify(eth_hdr[1]).decode()
    eth_hdr_info["eth_type"] = hex(eth_hdr[2])

    return eth_hdr_info

#  --------------------------- IP Header ---------------------------

# Prepare IP Header
def prepare_ip_hdr(src_ip, dst_ip, payload_len, proto_id):
    # IP Header Fields
    len_and_ver = 0x45
    type_of_service = 0
    packet_length = payload_len # IP header length (20 bytes) + Payload length (X bytes)
    packet_id = 101
    frag_flags_and_offset = 0
    ttl = 64
    proto_id = proto_id # The protocol ID for TCP = 6
    ip_checksum = 0
    src_addr = socket.inet_aton(src_ip)
    dst_addr = socket.inet_aton(dst_ip)

    # Craft the IP header
    ip_hdr = struct.pack("!BBHHHBBH4s4s", len_and_ver, type_of_service, packet_length, packet_id, frag_flags_and_offset,
                    ttl, proto_id, ip_checksum, src_addr, dst_addr)
    return ip_hdr


# Unpack IP Header
def unpack_ip_hdr(ip_hdr):
    # Length of IP header is 20 bytes (without options)
    ip_hdr = struct.unpack("!BBHHHBBH4s4s", ip_hdr)
    
    ip_hdr_info = {}
    ip_hdr_info["ip_protocol"] = ip_hdr[6]
    ip_hdr_info["src_ip"] = socket.inet_ntoa(ip_hdr[8])
    ip_hdr_info["dst_ip"] = socket.inet_ntoa(ip_hdr[9])

    return ip_hdr_info

def modify_ip_hdr(ip_hdr, src_ip, dst_ip):
    # Length of IP header is 20 bytes (without options)
    ip_hdr = struct.unpack("!BBHHHBBH4s4s", ip_hdr)
    
    src_addr = socket.inet_aton(src_ip)
    dst_addr = socket.inet_aton(dst_ip)
    ip_checksum = 0
    new_ip_hdr = struct.pack("!BBHHHBBH4s4s", ip_hdr[0], ip_hdr[1], ip_hdr[2], ip_hdr[3], ip_hdr[4],
                    ip_hdr[5], ip_hdr[6], ip_checksum, src_addr, dst_addr)
    return new_ip_hdr

#  --------------------------- TCP Header ---------------------------

def prepare_tcp_hdr(src_port, dst_port, tcp_checksum=0):
    # TCP Header Fields
    src_port = src_port
    dst_port = dst_port
    seq_no = 1001
    ack_no = 0
    data_offset_and_flags = 0x5002 # 4 bits for data offset, 6 bits for padding, and 6 bits for flags => Total 16 bits
    rx_window = 0xffff # Used the same value that I saw on Wireshark TCP SYN packet
    tcp_checksum = struct.pack("H", tcp_checksum) # convert checksum to bytes and use "string" format for it in the struct pack below.
    urgent = 0

    # Craft the TCP header (without Options)
    tcp_hdr = struct.pack("!HHLLHH2sH", src_port, dst_port, seq_no, ack_no, data_offset_and_flags, rx_window, tcp_checksum, urgent)
    return tcp_hdr

def prepare_tcp_pseudo_hdr(src_ip, dst_ip, tcp_hdr_len):
    # TCP Pseudo-Header
    src_addr = socket.inet_aton(src_ip)
    dst_addr = socket.inet_aton(dst_ip)
    reserved = 0
    proto = 6
    tcp_len = tcp_hdr_len

    # Craft the TCP pseudoheader
    tcp_pseudo_hdr = struct.pack("!4s4sBBH", src_addr, dst_addr, reserved, proto, tcp_len)   
    return tcp_pseudo_hdr 

# Unpack TCP Header (without options)
def unpack_tcp_hdr(tcp_hdr_without_opt):
    # Length of TCP header is atleast 20 bytes after IP header
    #tcp_hdr = struct.pack("!HHLLBBHHH", src_port, dst_port, seq_no, ack_no, data_offset_and_reserved, flags, rx_window, tcp_checksum, urgent)
    tcp_hdr_without_opt = struct.unpack("!HHLLBBHHH", tcp_hdr_without_opt)

    src_port = tcp_hdr_without_opt[0]
    dst_port = tcp_hdr_without_opt[1]

    tcp_hdr_info = {}
    tcp_hdr_info["src_port"] = src_port
    tcp_hdr_info["dst_port"] = dst_port

    return tcp_hdr_info

def modify_tcp_segment(tcp_segment, src_port, dst_port, tcp_checksum=0):
    # TCP segment is everything after IP header
    #tcp_hdr = struct.pack("!HHLLBBHHH", src_port, dst_port, seq_no, ack_no, data_offset_and_reserved, flags, rx_window, tcp_checksum, urgent)
    tcp_hdr_without_opt = tcp_segment[:20]
    tcp_hdr_without_opt = struct.unpack("!HHLLHH2sH", tcp_hdr_without_opt)

    src_port = src_port
    dst_port = dst_port
    tcp_checksum = struct.pack("H", tcp_checksum)
    
    new_tcp_hdr_without_opt = struct.pack("!HHLLHH2sH", src_port, dst_port, tcp_hdr_without_opt[2], tcp_hdr_without_opt[3], tcp_hdr_without_opt[4], tcp_hdr_without_opt[5], tcp_checksum, tcp_hdr_without_opt[7])
    new_tcp_segment = new_tcp_hdr_without_opt + tcp_segment[20:]

    return new_tcp_segment

#  --------------------------- IP Packets ---------------------------

# Check if packet is an IP packet.
def is_ip_pkt(pkt):
    eth_hdr = unpack_eth_hdr(pkt)
    # Check if its an IP packet. If not, then return
    if eth_hdr['eth_type'] != "0x800":
        return False
    return True


# checksum(msg) <-- computes 16-bit checksum (RFC 1071)
# - params(1):
#    -- msg: message to compute chksum of, split two bytes at a time
# - note: checksum is complement of 16-bit sum, incl carry
# - return value: 16-bit checksum
def checksum(msg):
    s = 0
    for i in range(0, len(msg), 2):
        s = s + ord((chr)(msg[i])) + (ord((chr)(msg[i + 1])) << 8)
    s = (s >> 16) + (s & 0xffff)
    s = s + (s >> 16)
    s = ~s & 0xffff
    return s