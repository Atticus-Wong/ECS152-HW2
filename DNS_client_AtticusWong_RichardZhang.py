"""
a.root-servers.net	198.41.0.4, 2001:503:ba3e::2:30	Verisign, Inc.
b.root-servers.net	170.247.170.2, 2801:1b8:10::b	University of Southern California,
Information Sciences Institute
c.root-servers.net	192.33.4.12, 2001:500:2::c	Cogent Communications
d.root-servers.net	199.7.91.13, 2001:500:2d::d	University of Maryland
e.root-servers.net	192.203.230.10, 2001:500:a8::e	NASA (Ames Research Center)
f.root-servers.net	192.5.5.241, 2001:500:2f::f	Internet Systems Consortium, Inc.
g.root-servers.net	192.112.36.4, 2001:500:12::d0d	US Department of Defense (NIC)
h.root-servers.net	198.97.190.53, 2001:500:1::53	US Army (Research Lab)
i.root-servers.net	192.36.148.17, 2001:7fe::53	Netnod
j.root-servers.net	192.58.128.30, 2001:503:c27::2:30	Verisign, Inc.
k.root-servers.net	193.0.14.129, 2001:7fd::1	RIPE NCC
l.root-servers.net	199.7.83.42, 2001:500:9f::42	ICANN
m.root-servers.net	202.12.27.33, 2001:dc3::35	WIDE Project
"""

# https://www.geeksforgeeks.org/computer-networks/dns-message-format/

import socket
import sys
import struct

ROOT_SERVERS = [
    "198.41.0.4",
    "170.247.170.2",
    "192.33.4.12",


]

DNS_SERVER_PORT = 53

PACKET_SIZE = 4096

#def send_dns(ip)

def solve(domain):
    """
    Build the DNS request payload using struct.pack
    """
    transaction_id = 0xFFFF
    flags = 0x0000
    question_count = 0x0001
    answer_count = 0x0000
    authority_count = 0x0000
    additional_rr_count = 0x0000
    header = struct.pack("!HHHHHH", transaction_id, flags, question_count, answer_count, authority_count, additional_rr_count)

    """
    Build question section 

    For wikipedia.org
    q_name should be "9 wikipedia 3 org 0"
    """

    
    words = domain.split('.')
    q_name = b""
    for word in words:
        q_name += struct.pack("B", len(word))
        q_name += word.encode()
    q_name += b"\x00"

    q_type = 0x0001
    q_class = 0x0001
    question = q_name + struct.pack("!HH", q_type, q_class)

    packet = header + question

    """
    Send packet to the root server
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(10.0)
    sock.sendto(packet, (ROOT_SERVERS[0], DNS_SERVER_PORT))

    response, client = sock.recvfrom(PACKET_SIZE)
    transaction_id, flags, question_count, answer_count, authority_count, additional_rr_count = struct.unpack("!HHHHHH", response[:12])

    offset = 12
    q_section_len = len(q_name) + 4

    offset = q_section_len + offset
    #print(additional_rr_count)

    #response[offset]

    for i in range(authority_count):
        if response[offset] == 192:
            #Compressed
            offset += 2
        else:
            #not compressed
            pass
        offset += 8
        rdlength = response[offset:offset + 2]
        value = struct.unpack("!H", rdlength)[0]
        offset += 2 + value
    
    ip = []
    for i in range(2):
        byte = response[offset]
        upper_half = byte & 0xF0
        lower_half = byte & 0x0F
        ip.append(upper_half)
        ip.append(lower_half)
        offset += 1
    
    #print(ip)
    ip_string = ".".join(str(i) for i in ip)



    #-------------TLD-----------

    print(ip_string)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(10.0)
    sock.sendto(packet, (ip_string, DNS_SERVER_PORT))
    response, client = sock.recvfrom(PACKET_SIZE)
    #print(response)

    """
    response, client = sock.recvfrom(PACKET_SIZE)
    transaction_id, flags, question_count, answer_count, authority_count, additional_rr_count = struct.unpack("!HHHHHH", response[:12])

    offset = 12
    q_section_len = len(q_name) + 4

    offset = q_section_len + offset
    #print(additional_rr_count)

    #response[offset]

    for i in range(authority_count):
        if response[offset] == 192:
            #Compressed
            offset += 2
        else:
            #not compressed
            pass
        offset += 8
        rdlength = response[offset:offset + 2]
        value = struct.unpack("!H", rdlength)[0]
        offset += 2 + value
    
    ip = []
    for i in range(2):
        byte = response[offset]
        upper_half = byte & 0xF0
        lower_half = byte & 0x0F
        ip.append(upper_half)
        ip.append(lower_half)
        offset += 1
    
    print(ip)
    ip_string = ".".join(str(i) for i in ip)
    print(ip_string)

    """
    

    """
    [ 12-byte HEADER ]
    [ QUESTION section:
        q_name (variable length)
        For wikipedia.org
        q_name should be "9 wikipedia 3 org 0"
                          1 9         1 3   1 = 15
        q_type 2 bytes
        q_class 2 bytes
    ]
    [ ANSWER section ]
    [ AUTHORITY section 

        DNS resource records:
        NAME        (variable, can be compressed)
            11000000 = 192 = NAME is always 2 bytes

        TYPE        2 bytes
        CLASS       2 bytes
        TTL         4 bytes
        RDLENGTH    2 bytes 
            The length of RDATA
        RDATA       variable length (RDLENGTH bytes)
    
    ]
    [ ADDITIONAL section ]
    """

    #print(transaction_id)

    pass

if __name__ == '__main__':
    domain = sys.argv[1]
    solve(domain)
    pass

