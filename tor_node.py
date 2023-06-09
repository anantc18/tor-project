#!/usr/bin/python3

import os, sys, socket
from custom_pkt import *
from fernet_encryption import *

# Obtain TOR configuration parameters from the environment
PRIVATE_KEY = os.environ.get('TOR_PRIVATE_KEY')
PREV_NEIGHBOR_IP = os.environ.get('TOR_PREV_NEIGHBOR')
NEXT_NEIGHBOR_IP = os.environ.get('TOR_NEXT_NEIGHBOR')
SELF_IP = os.environ.get('TOR_SELF_IP')
CIRCUIT_ID = int(os.environ.get('TOR_CIRCUIT_ID'))

# Some other constants
INTERFACE = 'eth0'      # 'eth0' will only exist in a CORE container and not in the VM
BUFSIZE = 0xFFFF
SIZE_CIRC_ID = 2

exit_dst_track = {}

# Function to encrypt packets when response is headed back from server to client
def encrypt_pkt(msg, key):    
    fernet_obj = Fernet(key)
    ciphertxt = fernet_obj.encrypt(msg)
    return ciphertxt

# Function to decrypt packets when request is headed from client to server
def decrypt_pkt(ciphertxt, key):
    fernet_obj = Fernet(key)
    msg = fernet_obj.decrypt(ciphertxt)    
    return msg

# Function to perform TOR routing operations
def onion_route(pkt):

    [_, pkt] = read_eth_hdr(pkt)                    # Discard ethernet header
    [ip_hdr, pkt_contents] = read_ip_hdr(pkt)       # Read IP header

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

    # Peel onion layer
    if (ip_hdr['src_ip'] == PREV_NEIGHBOR_IP):    

        # Decrypt packet and obtain its circuit ID
        try:
            encrypted_pkt = pkt_contents[SIZE_CIRC_ID:]
            pkt_circ_id = int.from_bytes(pkt_contents[0:SIZE_CIRC_ID], byteorder='big', signed=False)
            decrypted_pkt = decrypt_pkt(encrypted_pkt, PRIVATE_KEY)
        except:
            print('\nCould not decrypt packet')
            return      

        # Drop packet if it doesn't belong to known circuit or isn't a TOR packet at all
        if pkt_circ_id != CIRCUIT_ID:   
            return
        
        # Create payload to be forwarded to next TOR node
        new_payload = decrypted_pkt

        # Attach IP header to payload and craft packet to be sent

        if NEXT_NEIGHBOR_IP != '0.0.0.0':       # Other than EXIT node
            forward_pkt =  create_ip_hdr(src_ip=SELF_IP, dest_ip=NEXT_NEIGHBOR_IP, proto_id=IP_P_TCP, \
                                    payload_len=len(new_payload)) + new_payload
            final_dst = NEXT_NEIGHBOR_IP

        else:                                   # EXIT node
            [in_built_ip_hdr, _] = read_ip_hdr(new_payload)     # Packet after decryption contains the final IP header from client
            final_dst = in_built_ip_hdr['dest_ip']
            exit_dst_track[pkt_circ_id] = final_dst             # Track the various destinations; used for encrypting later
            forward_pkt = new_payload
        
        # Send packet on the wire
        sock.sendto(forward_pkt, (final_dst, 0))
        return

    # Add onion layer
    elif (NEXT_NEIGHBOR_IP != '0.0.0.0') and (ip_hdr['src_ip'] == NEXT_NEIGHBOR_IP):    

        # OPEN: What if the packet from NEXT_NEIGHBOR_IP isn't a TOR packet? How do we check?

        # Add circuit ID to packet and encrypt
        try:
            encrypted_pkt = CIRCUIT_ID.to_bytes(SIZE_CIRC_ID, byteorder='big') + encrypt_pkt(pkt_contents, PRIVATE_KEY)
            
        except:
            print('\nCould not encrypt packet')
            return      

        # Attach IP header to payload and craft packet to be sent
        forward_pkt =  create_ip_hdr(src_ip=SELF_IP, dest_ip=PREV_NEIGHBOR_IP, proto_id=IP_P_TCP, \
                                    payload_len=len(encrypted_pkt)) + encrypted_pkt
        
        # Send packet on the wire
        sock.sendto(forward_pkt, (PREV_NEIGHBOR_IP, 0))
        return
    
    elif NEXT_NEIGHBOR_IP == '0.0.0.0':         # EXIT node

        circ_id_list = list(exit_dst_track.keys())
        final_dst_list = list(exit_dst_track.values())

        if ip_hdr['src_ip'] in final_dst_list:

            circ_id = circ_id_list[final_dst_list.index(ip_hdr['src_ip'])]
            try:
                encrypted_pkt = circ_id.to_bytes(SIZE_CIRC_ID, byteorder='big') + encrypt_pkt(pkt, PRIVATE_KEY)
            except:
                print('\nCould not encrypt packet')
                return      

            # Attach IP header to payload and craft packet to be sent
            forward_pkt =  create_ip_hdr(src_ip=SELF_IP, dest_ip=PREV_NEIGHBOR_IP, proto_id=IP_P_TCP, \
                                    payload_len=len(encrypted_pkt)) + encrypted_pkt
        
            # Send packet on the wire
            sock.sendto(forward_pkt, (PREV_NEIGHBOR_IP, 0))

        return

    
    # Drop packets from non-TOR circuit nodes for now
    else:
        pass


if __name__=='__main__':

    # Create a raw socket and bind it to the interface you want to listen for TOR packets on
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sock.bind((INTERFACE, ETH_T_IP))

    print('\nStarting onion router...\n')
    
    # Keep listening for packets till eternity
    while(True):
        try:
            pkt = sock.recv(BUFSIZE)
            onion_route(pkt)
        except KeyboardInterrupt:       # Handle SIGINT
            print('\nTurning off onion router!\n')
            break
    
    # Clean up
    sock.close()
    exit(0)