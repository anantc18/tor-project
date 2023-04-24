#!/usr/bin/env python3
from calendar import c
import socket, sys, time, struct, random
# from scapy.all import *
import binascii
from custom_pkt2 import *

TOR_DIRECTORY = ['10.0.1.20', '10.0.2.20', '10.0.3.20', '10.0.4.20', '10.0.5.20']
KEYS = ['a'*256, 'b'*256, 'c'*256, 'd'*256, 'e'*256]
CIRC_ID = 0
TOR_PORT = 9050
ETH_P_IP = 0x0800
TOR_CLIENT_IP = '10.0.0.20'

# Keeps track of all dest_ip and dest_ports in the request packets. This will be used to forward the response back to the appropriate application port number
# PACKETS = {
#     '<src_port>' : [<dst_ip>, <dst_port>, <proto_id>]
# }
PACKETS = {} 

# The `circuits` dict stores all circuits created by the client and its corresponding intermediary TOR nodes.
# circuits = {
#       2: {
#           'nodes': ['10.0.0.2', '10.0.0.3' ,'10.0.0.4']
#           'keys': ['a'*256, 'b'*256, 'c'*256]
#       }
# }
circuits = {}

# Setup a socket for TOR
def setup_socket():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except socket.error as msg:
        print('error ' + str(msg[0]) + ': ' + msg[1])
        sys.exit() 
    
    global TOR_PORT
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    # sock.bind(('127.0.0.1', TOR_PORT))
    
    return sock

# Setup a TOR circuit
def setup_circ():
    tor_nodes = random.sample(TOR_DIRECTORY, 3)   # Randomly choose 3 nodes for TOR circuit
    shared_keys = random.sample(KEYS, 3)          # Randomly choose 3 keys for each TOR node 
    circ_id = random.randint(0, 65535)            # Randomly choose a cird_id. This should be unique in the TOR network.
    
    circuits[circ_id] = {}
    circuits[circ_id]['nodes'] = tor_nodes
    circuits[circ_id]['keys'] = shared_keys
    
    # global CIRC_ID
    # CIRC_ID = CIRC_ID + 1   # Everytime a new circuit is setup, the CIRC_ID is incremented by 1. 
    # circuits[CIRC_ID] = {}
    # circuits[CIRC_ID]['nodes'] = tor_nodes
    # circuits[CIRC_ID]['keys'] = shared_keys

    return circ_id

# Encrypt a message (in bytes)
def encrypt(msg, key=None):
    ciphertxt = msg
    return ciphertxt

# Decrypt a message (in bytes)
def decrypt(ciphertxt, key=None):
    msg = ciphertxt
    return msg

# Modify the TCP packet with new header values and return the updated packet
def modify_tcp_pkt(pkt, src_ip, src_port, dst_ip, dst_port):
    ip_hdr = modify_ip_hdr(pkt[:20], src_ip, dst_ip)
    tcp_seg = modify_tcp_segment(pkt[20:], src_port, dst_port, tcp_checksum=0)   # TCP segment = header + payload
    tcp_pseudo_hdr = prepare_tcp_pseudo_hdr(src_ip, dst_ip, len(tcp_seg))   

    # calculate checksum with pseudo header
    tcp_checksum = checksum(tcp_seg + tcp_pseudo_hdr)
    
    # Recreate tcp header with actual checksum value
    tcp_seg = modify_tcp_segment(pkt[20:], src_port, dst_port, tcp_checksum)

    new_pkt = ip_hdr + tcp_seg
    return new_pkt

# Encrypt packet thrice and forward to entry node.
def tor_encryption(circ_id, tor_nodes, pkt):
    pkt_ip_hdr = unpack_ip_hdr(pkt[:20])
    pkt_tcp_hdr = unpack_tcp_hdr(pkt[20:40])
    proto_id = pkt_ip_hdr['ip_protocol']
    circ_id_bytes = struct.pack('!H', circ_id)

    # Change the IP and TCP header for the main packet. Also, you'll have to change the TCP pseudo header if the IP header is changed.
    # This is for the packet from exit node --> server
    src_ip = tor_nodes[2]
    #src_port = TOR_PORT
    src_port = pkt_tcp_hdr['src_port']
    dst_ip = pkt_ip_hdr['dst_ip']
    dst_port = pkt_tcp_hdr['dst_port']

    # NOTE: For now, we're only considering TCP packet!! 
    if proto_id == 6:
        # This is what the exit node will see after decrypting initial received packet.
        pkt0 = modify_tcp_pkt(pkt, src_ip, src_port, dst_ip, dst_port)
    # else:
    #     pkt0 = modify_ip_pkt(pkt, src_ip, dst_ip)

    # Encrypt the packet using exit nodes key
    # Add IP header which should be for middle node --> exit node
    src_ip = tor_nodes[1]
    dst_ip = tor_nodes[2]
    exit_node_key = circuits[circ_id]['keys'][2]
    ip_hdr1 = prepare_ip_hdr(src_ip, dst_ip, len(pkt0)+2 , proto_id)   # Here, IP packet length will be len(pkt0) + len(circ_id) = len(pkt0) + 2
    pkt1 = ip_hdr1 + circ_id_bytes + encrypt(pkt0, exit_node_key)

    # Encrypt the packet using middle nodes key
    # Add IP header which should be for entry node --> middle node
    src_ip = tor_nodes[0]
    dst_ip = tor_nodes[1]
    middle_node_key = circuits[circ_id]['keys'][1]
    ip_hdr2 = prepare_ip_hdr(src_ip, dst_ip, len(pkt1)+2 , proto_id)   # Here, IP packet length will be len(pkt1) + len(circ_id) = len(pkt1) + 2
    pkt2 = ip_hdr2 + circ_id_bytes + encrypt(pkt1, middle_node_key)

    # Encrypt the packet using entry nodes key
    # Add IP header which should be for client --> entry node
    src_ip = TOR_CLIENT_IP
    dst_ip = tor_nodes[0]
    entry_node_key = circuits[circ_id]['keys'][0]
    ip_hdr3 = prepare_ip_hdr(src_ip, dst_ip, len(pkt2)+2 , proto_id)   # Here, IP packet length will be len(pkt2) + len(circ_id) = len(pkt2) + 2
    pkt3 = ip_hdr3 + circ_id_bytes + encrypt(pkt2, entry_node_key)

    return pkt3

# Decrypt packet thrice and forward to application.
def tor_decryption(circ_id, tor_nodes, pkt):
    # We receive packet which is encrypted thrice
    pkt3 = pkt

    # Decrypt using entry node key
    entry_node_key = circuits[circ_id]['keys'][0]
    pkt2 = decrypt(pkt3[22:], entry_node_key)

    # Decrypt using entry node key
    middle_node_key = circuits[circ_id]['keys'][1]
    pkt1 = decrypt(pkt2[22:], entry_node_key)

    # Decrypt using entry node key
    exit_node_key = circuits[circ_id]['keys'][2]
    pkt0 = decrypt(pkt1[22:], entry_node_key)

    return pkt0


def onion_route(circ_id, tor_nodes, pkt):
    print(f"Received Packet ==> Src IP: {unpack_ip_hdr(rcv_pkt[:20])['src_ip']},  Dst IP: {unpack_ip_hdr(rcv_pkt[:20])['dst_ip']}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

    pkt_ip_hdr = unpack_ip_hdr(pkt[:20])
    src_ip = pkt_ip_hdr['src_ip']
    dst_ip = pkt_ip_hdr['dst_ip']
    proto_id = pkt_ip_hdr['ip_protocol']
    
    print(f"Received IP packet with protocol {proto_id}")
    # Discard all non-TCP packets.
    if proto_id != 6:
        return

    pkt_tcp_hdr = unpack_tcp_hdr(pkt[20:40])
    src_port = pkt_tcp_hdr['src_port']
    dst_port = pkt_tcp_hdr['dst_port']

    entry_node = tor_nodes[0]
    # If packet is request from client to server, then encrypt the packet three times and send it to the entry node.
    if pkt_ip_hdr['src_ip'] == '127.0.0.1':
        print(f"Received Packet from localhost:{src_port}")
        # Keep record of packet details that were sent from the clients source port.
        if src_port not in PACKETS:
            PACKETS[src_port] = []
        PACKETS[src_port] = [dst_ip, dst_port, proto_id]

        final_pkt = tor_encryption(circ_id, tor_nodes, pkt)
        sock.sendto(final_pkt, (tor_nodes[0], TOR_PORT))

    # If packet is a response from a server (via entry node), then decrypt the packet and forward it to the application that it was intended for. 
    elif pkt_ip_hdr['src_ip'] == entry_node:
        print(f"Received Packet from entry node")
        
        final_pkt = tor_decryption(circ_id, tor_nodes, pkt)

        # Find out which port on the client system to forward to. 
        final_pkt_ip_hdr = unpack_ip_hdr(pkt[:20])
        final_pkt_tcp_hdr = unpack_tcp_hdr(pkt[20:40])
        dst_port = final_pkt_tcp_hdr['dst_port']
        if dst_port in PACKETS:
            if not final_pkt_ip_hdr['src_ip'] == PACKETS[dst_port][0]:
                print("Some Error in Logic!!")
        
        sock.sendto(final_pkt, ('127.0.0.1', dst_port))

    return


if __name__ == "__main__":
    circ_id = setup_circ()
    tor_nodes = circuits[circ_id]['nodes']

    sock = setup_socket()
    # sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_IP))
    # sock.bind(('eth0', TOR_PORT))
    print(sock)
    while(1):
        rcv_pkt = sock.recvfrom(0xffff)[0]
        #rcv_pkt = rcv_pkt[14:]  # Remove 14 bytes of Ethernet header
        onion_route(circ_id, tor_nodes, rcv_pkt)

        
