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

import socket
import sys
import struct

ROOT_SERVERS = [
    "198.41.0.4",
    "170.247.170.2",
    "192.33.4.12",
    "199.7.91.13",
    "192.203.230.10"
]

DNS_SERVER_PORT = 53
PACKET_SIZE = 4096
HTTP_PORT = 80
R_TYPE_VAL_TO_NAME = {
    1: "A",
    2: "NS",
    5: "CNAME",
    28: "AAAA"
}


def build_dns_packet(domain):
    transaction_id = 0xFFFF
    flags = 0x0000
    question_count = 0x0001
    answer_count = 0x0000
    authority_count = 0x0000
    additional_rr_count = 0x0000
    header = struct.pack("!HHHHHH", transaction_id, flags, question_count, answer_count, authority_count, additional_rr_count)
    
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
    return packet, q_name

def send_dns_packet(packet, dns_ip):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(10.0)
    sock.sendto(packet, (dns_ip, DNS_SERVER_PORT))

    response, client = sock.recvfrom(PACKET_SIZE)
    return response

def parse_dns_records(response, offset, count):
    records = {}
    ip_string = ""
    for i in range(count):
        if response[offset] >= 192:
            offset += 2
        else:
            while response[offset] != 0:
                offset += 1
            offset += 1

        r_type = response[offset:offset+2]
        r_type_val = struct.unpack("!H", r_type)[0]
        offset += 2 #TYPE
        offset += 2 #CLASS
        offset += 4 #TTL

        rdlength = response[offset:offset + 2]
        rdlength_val = struct.unpack("!H", rdlength)[0]
        offset += 2 #RDLENGTH

        """
        A (1), NS (2), CNAME (5), SOA (6), PTR (12), MX (15), AAAA (28), SRV (33), and TXT (16)

        NS: a.root-servers.net
        A: 192.168.0.134
        """
        r_data = None
        #Need to advance offset in each case too *
        if r_type_val == 1:
            #rdata contains an A record
            ip_bytes = response[offset:offset+4]
            ip_string = ".".join(str(i) for i in ip_bytes)
            r_data = ip_string
            offset += rdlength_val
            records[R_TYPE_VAL_TO_NAME[r_type_val]] = r_data
        elif r_type_val == 2:
            name = ""
            ns_offset = offset
            while response[ns_offset] != 0:
                if response[ns_offset] >= 192:
                    pointer = struct.unpack("!H", response[ns_offset:ns_offset+2])[0] & 0x3FFF
                    ns_offset = pointer
                    continue
                label_len = response[ns_offset]
                ns_offset += 1
                name += response[ns_offset:ns_offset+label_len].decode() + "."
                ns_offset += label_len
            name = name.rstrip(".")
            r_data = name
            offset += rdlength_val
            records[R_TYPE_VAL_TO_NAME[r_type_val]] = r_data
        else:
            offset += rdlength_val
    
    
    return records, offset

def send_http_request(ip_string, domain):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10.0)
    sock.connect((ip_string, HTTP_PORT))

    request = f"GET / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n"
    sock.sendall(request.encode())
    response = sock.recv(PACKET_SIZE)

    return response

def get_final_ip(domain):
    #-------------ROOT-----------
    packet, q_name = build_dns_packet(domain)
    response = send_dns_packet(packet, ROOT_SERVERS[0])
    transaction_id, flags, question_count, answer_count, authority_count, additional_rr_count = struct.unpack("!HHHHHH", response[:12])
    offset = 12 + len(q_name) + 4 

    _, offset = parse_dns_records(response, offset, authority_count) # No IP in the authority section
    records, offset = parse_dns_records(response, offset, additional_rr_count)
    
    #print(f"TLD IP: {tld_ip_string}")

    #-------------TLD-----------

    packet, q_name = build_dns_packet(domain)
    response = send_dns_packet(packet, records["A"])
    transaction_id, flags, question_count, answer_count, authority_count, additional_rr_count = struct.unpack("!HHHHHH", response[:12])
    offset = 12 + len(q_name) + 4 

    authority_records, offset = parse_dns_records(response, offset, authority_count) # No IP in the authority section
    additional_records, offset = parse_dns_records(response, offset, additional_rr_count)

    if "A" not in additional_records and "NS" in authority_records:
        #recursively query the NS domain
        # ns0229.secondary.cloudflare.com
        print(f"name server found {authority_records['NS']}")
        return get_final_ip(authority_records["NS"])
    
    auth_ip = additional_records["A"]


    #-------------AUTHORITATIVE-----------
    #print(records)
    packet, q_name = build_dns_packet(domain)
    response = send_dns_packet(packet, auth_ip)
    transaction_id, flags, question_count, answer_count, authority_count, additional_rr_count = struct.unpack("!HHHHHH", response[:12])
    offset = 12 + len(q_name) + 4 

    answer_records, offset = parse_dns_records(response, offset, answer_count)
    final_ip = answer_records["A"]
    return final_ip

def solve(domain):
    final_ip = get_final_ip(domain)
    response = send_http_request(final_ip, domain)
    print(response)



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
    [ ADDITIONAL section 
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
    """

    #print(transaction_id)

    pass

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Incorrect number of args. Expected ./DNS_client_AtticusWong_RichardZhang.py <domain>")
        sys.exit(1)
    domain = sys.argv[1]
    solve(domain)

