import struct, socket

#---------------------- Constants-----------------------------------#

HW_ADDR_LEN = 6 
IP_ADDR_LEN = 4

ETHLEN = (2 * HW_ADDR_LEN + 2)
ARPLEN = (2 * HW_ADDR_LEN + 2 * IP_ADDR_LEN + 8)
IPLEN = 20
ICMPLEN = 8
TCPLEN = 20
UDPLEN = 8
PHLEN = 12

ETH_T_ALL = 0x0003
ETH_T_IP = 0x0800
ETH_T_ARP = 0x0806
ETH_T_CUSTOM = 0x0101

ARP_HW_ETH = 1

IP_P_ICMP = 1
IP_P_TCP = 6
IP_P_UDP = 17

ICMP_ECHO_REQ = 8
ICMP_ECHO_REP = 0

ARP_REQUEST = 1
ARP_REPLY = 2

TCP_F_FIN = 0x01
TCP_F_SYN = 0x02
TCP_F_RST = 0x04
TCP_F_PSH = 0x08
TCP_F_ACK = 0x10
TCP_F_URG = 0x20
TCP_F_ECE = 0x40
TCP_F_CWR = 0x80


#---------------------- Checksum -------------------------------------#
def checksum(msg):
    # Calculates the Internet Checksum (16-bit)
    # Input: Bytes-object of any length
    # Output: Bytes-object of length 2 bytes
    # Note: Checksum follows the byte-order of the input
    # Credits: Teaching staff 14-742 Spring 2023 (Lab 1 Starter Code)

    s = 0
    for i in range(0, len(msg), 2):
        s = s + ord((chr)(msg[i])) + (ord((chr)(msg[i + 1])) << 8)
    s = (s >> 16) + (s & 0xffff)
    s = s + (s >> 16)
    s = ~s & 0xffff

    s = struct.pack("!H", s)                    # Convert to little-endian format
    s = int.from_bytes(s, byteorder='little')

    return s

#--------------------- MAC Address String to Bytes -------------------#

def mac_str2byt(addr_str):
    # Converts MAC addresses written in string notation to bytes-object
    # Input: MAC address written in "aa:bb:cc:dd:ee:ff" format
    # Output: MAC address as a bytes-object in network-byte order

    try:
        addr_str = addr_str.split(':')
        addr_byt = b''
        for i in range(HW_ADDR_LEN):
            addr_byt += int(addr_str[i], 16).to_bytes(1, byteorder='big', signed=False)
        return addr_byt

    except Exception as e:
        print('Incorrect MAC address - wrong string notation:', e) 


#--------------------- MAC Address Bytes to String -------------------#

def mac_byt2str(addr_byt):
    # Converts MAC address expressed as bytes to string notation
    # Input: MAC address as a bytes-object in network-byte order
    # Output: MAC address written in "aa:bb:cc:dd:ee:ff" format

    try:
        addr_str = list(struct.unpack("!ssssss", addr_byt))
        for i in range(HW_ADDR_LEN):
            addr_str[i] = str(hex(int.from_bytes(addr_str[i], byteorder='little')))
            _, addr_str[i] = addr_str[i].split('0x')
        addr_str = ':'.join(addr_str)
        return addr_str

    except Exception as e:
        print('Incorrect MAC address - wrong number of bytes:', e) 

#---------------------- Ethernet Header -------------------------------------#

def create_eth_hdr(src_mac, dest_mac, eth_typ = ETH_T_IP):
    # Creates ethernet headers for raw sockets
    # Input: MAC addresses written as strings in "aa:bb:cc:.." notation
    # Optional input: Integer code for the protocol within Ethernet
    # Output: Bytes-object of length 14 bytes in network-byte order

    try:
        dest_mac = mac_str2byt(dest_mac)
        src_mac = mac_str2byt(src_mac)
        eth_typ = eth_typ.to_bytes(2, byteorder='big', signed=False)
        eth_hdr = dest_mac + src_mac + eth_typ
        return eth_hdr

    except Exception as e:
        print('Incorrect ethernet header parameters:', e)


def read_eth_hdr(pkt):
    # Strip off and decode ethernet header from a packet
    # Input: Bytes-object of any length in network-byte order
    # Output: (1) Datagram with the ethernet header bytes removed, (2) Dictionary containing Ethernet header values

    try:
        eth_hdr = {'src_mac':'', 'dest_mac':'', 'eth_typ':''}
        eth_hdr['dest_mac'] = mac_byt2str(pkt[0:6])
        eth_hdr['src_mac'] = mac_byt2str(pkt[6:12])
        eth_hdr['eth_typ'] = int.from_bytes(pkt[12:14], byteorder='big', signed=False)
        return [eth_hdr, pkt[ETHLEN:]]

    except Exception as e:
        print('Cannot read ethernet header, corrupt packet: ', e)


#---------------------- ARP Header -------------------------------------#

def create_arp_hdr( src_ip, dest_ip, src_mac, dest_mac = "00:00:00:00:00:00", opcode = ARP_REQUEST):
    # Creates ARP headers for raw sockets
    # Inputs: Source MAC address written as a "aa:bb:.." string, source & destination IPv4 addresses written as "xx.yy.zz.ww" strings
    # Optional inputs: ARP opcode
    # Output: Bytes-object of length 28 bytes in network-byte order

    try: 
        hw_typ = ARP_HW_ETH                           # Deafult hardware layer beneath ARP is Ethernet with code 0
        proto_typ = ETH_T_IP                          # Default protocol layer above ARP is IP with code 0x800 or 2048
        hw_addr_len = HW_ADDR_LEN                     # MAC address lengths are 6 bytes
        proto_addr_len = IP_ADDR_LEN                  # IP addresses lengths are 4 bytes
        dest_mac = mac_str2byt(dest_mac)
        src_mac = mac_str2byt(src_mac)
        src_ip = socket.inet_aton(src_ip)
        dest_ip = socket.inet_aton(dest_ip)

        arp_hdr = struct.pack("!HHBBH6s4s6s4s", hw_typ, proto_typ, hw_addr_len, proto_addr_len, opcode, src_mac, src_ip, dest_mac, dest_ip)
        return arp_hdr

    except Exception as e: 
        print('Incorrect ARP header parameters:', e)


def read_arp_hdr(pkt):
    # Strip off and decode ARP header from a packet
    # Input: Bytes-object of any length in network-byte order starting with the ARP header
    # Output: (1) Datagram with the ARP header bytes removed, (2) Dictionary containing ARP header values

    try:
        arp_hdr = {'hw_typ':'', 'proto_typ':'', 'hw_addr_len':'', 'proto_addr_len':'', 'dest_mac':'', 'src_mac':'', 'src_ip':'', 'dest_ip':''}
        
        arp_hdr['hw_typ'] = int.from_bytes(pkt[0:2], byteorder='big', signed=False)
        arp_hdr['proto_typ'] = int.from_bytes(pkt[2:4], byteorder='big', signed=False)
        arp_hdr['hw_addr_len'] = int.from_bytes(pkt[4:5], byteorder='big', signed=False)
        arp_hdr['proto_addr_len'] = int.from_bytes(pkt[5:6], byteorder='big', signed=False)
        arp_hdr['opcode'] = int.from_bytes(pkt[6:8], byteorder='big', signed=False)
        arp_hdr['src_mac'] = mac_byt2str(pkt[8:14])
        arp_hdr['src_ip'] = socket.inet_ntoa(pkt[14:18])
        arp_hdr['dest_mac'] = mac_byt2str(pkt[18:24])
        arp_hdr['dest_ip'] = socket.inet_ntoa(pkt[24:28])
        return [arp_hdr, pkt[ARPLEN:]]

    except Exception as e:
        print('Cannot read ARP header, corrupt packet: ', e)

#------------------------- IP Header -------------------------------------#

def create_ip_hdr(src_ip, dest_ip, proto_id, payload_len, ver_and_hlen = 69, tos = 0, packet_id = 0, frag_flags_and_offset = 0, ttl = 16):
    # Creates IP headers for raw sockets (doesn't support IP Options)
    # Inputs: Source & destination IP addresses written as "xx.yy.zz.ww" strings, IP Protocol ID (1 byte) and payload length (2 bytes) as integers
    # Optional inputs: IP version and header (1 byte), Type of Service (1 byte), Packet ID (2 bytes), Fragmentation flags & offset (2 bytes), TTL (1 byte) - as integers
    # Output: Bytes-object of varible length in network-byte order

    try:
        src_ip = socket.inet_aton(src_ip)
        dest_ip = socket.inet_aton(dest_ip)
        packet_len = payload_len + IPLEN           # Length of IP header without options is 20 bytes

        checksum_ip = checksum(struct.pack("!BBHHHBBH4s4s", ver_and_hlen, tos, packet_len, packet_id, frag_flags_and_offset, ttl, proto_id, 0, src_ip, dest_ip))

        ip_hdr = struct.pack("!BBHHHBBH4s4s", ver_and_hlen, tos, packet_len, packet_id, frag_flags_and_offset, ttl, proto_id, checksum_ip, src_ip, dest_ip)
        return ip_hdr

    except Exception as e:
        print('Incorrect IP header parameters:', e)


def read_ip_hdr(pkt):
    # Strip off and decode IP header from a packet
    # Input: Bytes-object of any length in network-byte order starting with the IP header
    # Output: (1) Datagram with the IP header bytes removed, (2) Dictionary containing IP header values
    # Note: IP header options are currently not supported
    # Note: Checksum is not verified

    try:
        ip_hdr = {'ver_and_hlen':'', 'tos':'', 'packet_len':'', 'packet_id':'', 'frag_flags_and_offset':'', 'ttl':'', 'proto_id':'', 'src_ip':'', 'dest_ip':''}
        
        ip_hdr['ver_and_hlen'] = int.from_bytes(pkt[0:1], byteorder='big', signed=False)
        ip_hdr['tos'] = int.from_bytes(pkt[1:2], byteorder='big', signed=False)
        ip_hdr['packet_len'] = int.from_bytes(pkt[2:4], byteorder='big', signed=False)
        ip_hdr['packet_id'] = int.from_bytes(pkt[4:6], byteorder='big', signed=False)
        ip_hdr['frag_flags_and_offset'] = int.from_bytes(pkt[6:8], byteorder='big', signed=False)
        ip_hdr['ttl'] = int.from_bytes(pkt[8:9], byteorder='big', signed=False)
        ip_hdr['proto_id'] = int.from_bytes(pkt[9:10], byteorder='big', signed=False)
        # ip_hdr checksum ignored
        ip_hdr['src_ip'] = socket.inet_ntoa(pkt[12:16])
        ip_hdr['dest_ip'] = socket.inet_ntoa(pkt[16:20])

        assert (len(pkt[IPLEN:]) == (ip_hdr['packet_len']-IPLEN))
        return [ip_hdr, pkt[IPLEN:]]

    except Exception as e:
        print('Cannot read IP header, corrupt packet: ', e)

#------------------------- ICMP Header -------------------------------------#

def create_icmp_hdr(type = ICMP_ECHO_REQ, code = 0, msg_id = 1, seq_num = 1):
    # Create ICMP headers for raw sockets
    # Inputs: ICMP type and code values, message ID (2 bytes) and sequence numbers (2 bytes) - as integers
    # Note: Default case is an ICMP Echo Request
    # Output: Bytes-object of length 8 bytes in network-byte order

    try:
        checksum_icmp = checksum(struct.pack("!BBHHH", type, code, 0, msg_id, seq_num))

        icmp_hdr = struct.pack("!BBHHH", type, code, checksum_icmp, msg_id, seq_num)
        return icmp_hdr

    except Exception as e:
        print('Incorrect ICMP header parameters:', e)


def read_icmp_hdr(pkt):
    # Strip off and decode ICMP header from a packet
    # Input: Bytes-object of any length in network-byte order starting with the ICMP header
    # Output: (1) Datagram with the ICMP header bytes removed, (2) Dictionary containing ICMP header values
    # Note: Checksum is not verified

    try:
        icmp_hdr = {'type':'', 'code':'', 'msg_id':'', 'seq_num':''}
        icmp_hdr['type'] = int.from_bytes(pkt[0:1], byteorder='big', signed=False)
        icmp_hdr['code'] = int.from_bytes(pkt[1:2], byteorder='big', signed=False)
        # icmp_hdr checksum ignored
        icmp_hdr['msg_id'] = int.from_bytes(pkt[4:6], byteorder='big', signed=False)
        icmp_hdr['seq_num'] = int.from_bytes(pkt[6:8], byteorder='big', signed=False)
        return [icmp_hdr, pkt[ICMPLEN:]]

    except Exception as e:
        print('Cannot read ICMP header, corrupt packet: ', e)

#--------------------------- TCP Header -------------------------------------#

def create_tcp_hdr(src_ip, dest_ip, src_port, dest_port, seq_num = 1, ack_num = 0, flags = TCP_F_SYN, rx_window = 1024):
    # Creates TCP headers for raw sockets
    # Inputs: Source and destination IP addresses as "aa.bb.cc.dd" strings, source and destination port numbers (2 bytes) as integers
    # Optional inputs: Sequence number (4 bytes), acknowledgement number (4 bytes), flags (1 byte), receiver window size (2 bytes) - as integers
    # Note: Default case is of a SYN header
    # Note: TCP options (and urgent pointer) are not implemented and overall header length is considered constant
    # Output: Bytes-object of length 20 bytes in network-byte order

    try:
        src_ip = socket.inet_aton(src_ip)
        dest_ip = socket.inet_aton(dest_ip)
        ip_proto = IP_P_TCP
        tcp_len = TCPLEN

        pseduo_hdr = struct.pack("!4s4sHH", src_ip, dest_ip, ip_proto, tcp_len)
        data_offset_and_reserved = 5<<4         # Length of TCP header (20 bytes) in 32 bit words as first 4 bits of a byte
        urgent = 0

        checksum_tcp = checksum(struct.pack("!12sHHLLBBHHH", pseduo_hdr, src_port, dest_port, seq_num, ack_num, \
                        data_offset_and_reserved, flags, rx_window, 0, urgent))
        
        tcp_hdr = struct.pack("!HHLLBBHHH", src_port, dest_port, seq_num, ack_num, data_offset_and_reserved, flags, rx_window, checksum_tcp, urgent)
        return tcp_hdr

    except Exception as e:
        print('Incorrect TCP header parameters:', e)


def read_tcp_hdr(pkt):
    # Strip off and decode TCP header from a packet
    # Input: Bytes-object of any length in network-byte order starting with the TCP header
    # Output: (1) Datagram with the TCP header bytes removed, (2) Dictionary containing TCP header values
    # Note: TCP header options are currently not supported
    # Note: Checksum is not verified

    try:
        tcp_hdr = {'src_port':'', 'dest_port':'', 'seq_num':'', 'ack_num':'', 'data_offset_and_reserved':'', 'flags':'', 'rx_window':'', 'urgent':''}

        tcp_hdr['src_port'] = int.from_bytes(pkt[0:2], byteorder='big', signed=False)
        tcp_hdr['dest_port'] = int.from_bytes(pkt[2:4], byteorder='big', signed=False)
        tcp_hdr['seq_num'] = int.from_bytes(pkt[4:8], byteorder='big', signed=False)
        tcp_hdr['ack_num'] = int.from_bytes(pkt[8:12], byteorder='big', signed=False)
        tcp_hdr['data_offset_and_reserved'] = int.from_bytes(pkt[12:13], byteorder='big', signed=False)
        tcp_hdr['flags'] = int.from_bytes(pkt[13:14], byteorder='big', signed=False)
        tcp_hdr['rx_window'] = int.from_bytes(pkt[14:16], byteorder='big', signed=False)
        # tcp_hdr checksum ignored
        tcp_hdr['urgent'] = int.from_bytes(pkt[18:20], byteorder='big', signed=False)
        
        return [tcp_hdr, pkt[TCPLEN:]]

    except Exception as e:
        print('Cannot read TCP header, corrupt packet: ', e)

    
