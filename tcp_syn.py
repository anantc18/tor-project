#!/usr/bin/env python3

import socket, sys, time, struct

def setup_connection(src_ip, src_port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except socket.error as msg:
        print('error ' + str(msg[0]) + ': ' + msg[1])
        sys.exit() 
    
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    return sock


def prepare_ip_hdr(src_ip, dst_ip):
    # IP Header Fields
    len_and_ver = 0x45
    type_of_service = 0
    packet_length = 40 # IP header length + TCP header and data length. In this case, 20 bytes of IP header + 20 bytes of TCP header = 40 bytes
    packet_id = 101
    frag_flags_and_offset = 0
    ttl = 64
    proto_id = 6 # The protocol ID for TCP = 6
    ip_checksum = 0
    src_addr = socket.inet_aton(src_ip)
    dst_addr = socket.inet_aton(dst_ip)

    # Craft the IP header
    ip_hdr = struct.pack("!BBHHHBBH4s4s", len_and_ver, type_of_service, packet_length, packet_id, frag_flags_and_offset,
                    ttl, proto_id, ip_checksum, src_addr, dst_addr)
    return ip_hdr

def prepare_tcp_hdr(src_port, dst_port, tcp_checksum=0):
    # TCP Header Fields
    src_port = src_port
    dst_port = dst_port
    seq_no = 1001
    ack_no = 0
    # 4 bits for data offset, 6 bits for padding, and 6 bits for flags => Total 16 bits
    #       Data offset = no. of 32 bit words = 5 (0101 in bits)
    #       Padding = 0 = 000000 (in bits)
    #       Flag for SYN packet = 000010 (in bits)
    # Final = 0101 0000 0000 0010 = 0x5002
    data_offset_and_flags = 0x5002
    rx_window = 0xffff # Used the same value that I saw on Wireshark TCP SYN packet
    tcp_checksum = struct.pack("H", tcp_checksum) # convert checksum to bytes and use "string" format for it in the struct pack below.
    urgent = 0

    # # Options Header Reference : https://www.ietf.org/rfc/rfc793.txt 
    # # MSS can be added in the Options header. The format for that is:
    # #               Kind = 2, Length = 4, and MSS = 1500 bytes (From table in RFC)
    # # Note: Kind (takes 1 byte) + Length (takes 1 byte) + Max Segment Size (takes 2 bytes) ==> Total 4 bytes
    # mss_kind_and_type = 0x24 
    # mss = 1500  # value in bytes
    # eol = 0 # End of Option List --> It takes 1 byte 
    # padding = 0 # This will be 7 bytes long since the TCP header has to end at a multiple of 4 bytes (or) 32 bits

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

# Prepare the header with proper header fields and create and return a packet
def prepare_packet(src_ip, src_port, dst_ip, dst_port):
    ip_hdr = prepare_ip_hdr(src_ip, dst_ip)
    tcp_hdr = prepare_tcp_hdr(src_port, dst_port)
    tcp_pseudo_hdr = prepare_tcp_pseudo_hdr(src_ip, dst_ip, len(tcp_hdr))

    # calculate checksum with pseudo header
    tcp_checksum = checksum(tcp_hdr + tcp_pseudo_hdr)
    
    # Recreate tcp header with actual checksum value
    tcp_hdr = prepare_tcp_hdr(src_port, dst_port, tcp_checksum)

    pkt = ip_hdr + tcp_hdr
    return pkt


def send_packet(sock, pkt, dst_ip, dst_port):
    sock.sendto(pkt, (dst_ip, dst_port))


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


if __name__ == "__main__":

    src_ip = "127.0.0.1"
    src_port = 44444
    dst_ip = "10.0.6.20"
    dst_port = 44445

    sock1 = setup_connection(src_ip, src_port)
    send_packet(sock1, prepare_packet(src_ip, src_port, dst_ip, dst_port), '127.0.0.1', 0)

    # sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # sock2.bind(('127.0.0.1', 44444))
    # print(sock2)
    # response = sock2.recvfrom(0xffff)

    # print(response)
    
