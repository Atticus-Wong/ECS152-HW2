import socket
import sys
import struct
from collections import defaultdict
import time

ROOT_SERVERS = [
    "198.41.0.4",
    "170.247.170.2",
    "192.33.4.12",
    "199.7.91.13",
    "192.203.230.10",
    "192.5.5.241",
    "192.112.36.4",
    "198.97.190.53",
    "192.36.148.17",
    "192.58.128.30",
    "193.0.14.129",
    "199.7.83.42",
    "202.12.27.33"
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
    start_time = time.time()
    sock.sendto(packet, (dns_ip, DNS_SERVER_PORT))
    try:
        response, client = sock.recvfrom(PACKET_SIZE)
        end_time = time.time()
        sock.close()
    except socket.timeout:
        sock.close()
        return None, 0
    rtt = (end_time - start_time) * 1000 #in ms
    return response, rtt

def parse_dns_records(response, offset, count):
    records = defaultdict(list)
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
        """
        r_data = None
        #Need to advance offset in each case too *
        if r_type_val == 1:
            #rdata contains an A record
            ip_bytes = response[offset:offset+4]
            ip_string = ".".join(str(i) for i in ip_bytes)
            r_data = ip_string
            offset += rdlength_val
            records[R_TYPE_VAL_TO_NAME[r_type_val]].append(r_data)
        elif r_type_val == 2 or r_type_val == 5:
            name_groups = []
            name_offset = offset
            while response[name_offset] != 0:
                if response[name_offset] >= 192:
                    # first 2 bits are 1s which means name is compressed
                    # the next 14 bits are the offset to locate the actual name
                    pointer = struct.unpack("!H", response[name_offset:name_offset+2])[0]
                    pointer = pointer & 0x3FFF #mask to return only the last 14 bits
                    name_offset = pointer
                    continue
                word_len = response[name_offset]
                name_offset += 1
                name_groups.append(str(response[name_offset:name_offset+word_len].decode()))
                name_offset += word_len
            name = ".".join(name for name in name_groups)
            r_data = name
            offset += rdlength_val
            records[R_TYPE_VAL_TO_NAME[r_type_val]].append(r_data)
        elif r_type_val == 28:
            #AAAA record
            ip_bytes = response[offset:offset+16]
            ipv6_groups = []
            for i in range(0, 16, 2):
                ipv6_groups.append(ip_bytes[i:i+2].hex())
            ip_string = ":".join(hex for hex in ipv6_groups)
            r_data = ip_string
            offset += rdlength_val
            records[R_TYPE_VAL_TO_NAME[r_type_val]].append(r_data)
        else:
            offset += rdlength_val
    
    return records, offset

def print_records(sections):
    combined_records = defaultdict(list)
    for record_name in ["A", "NS", "CNAME", "AAAA"]:
        for section in sections:
            if record_name in section:
                for val in section[record_name]:
                    combined_records[record_name].append(val)

    for record_name in combined_records:
        for record in combined_records[record_name]:
            print(f"{record_name} : {record}")

def send_http_request(ip_string, domain):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10.0)
    start_time = time.time()
    sock.connect((ip_string, HTTP_PORT))
    request = f"GET / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n"
    print("--------------------------------------------")
    print(f"Making HTTP request to {ip_string}")
    print("--------------------------------------------")
    sock.sendall(request.encode())
    response = sock.recv(PACKET_SIZE)
    end_time = time.time()
    sock.close()
    rtt = (end_time - start_time) * 1000
    return response, rtt

def get_final_ip(domain):
    #-------------ROOT-----------
    packet, q_name = build_dns_packet(domain)

    for root_server in ROOT_SERVERS:
        print("--------------------------------------------")
        print(f"Querying {root_server} for {domain}")
        print("--------------------------------------------")
        response, root_rtt = send_dns_packet(packet, root_server)
        if response is not None:
            break
    if response is None:
        raise Exception("All root servers timed out")
    transaction_id, flags, question_count, answer_count, authority_count, additional_rr_count = struct.unpack("!HHHHHH", response[:12])
    offset = 12 + len(q_name) + 4 

    root_auth_records, offset = parse_dns_records(response, offset, authority_count) # No IP in the authority section
    root_addl_records, offset = parse_dns_records(response, offset, additional_rr_count)
    tld_ip_string = root_addl_records["A"][0]

    print_records([root_auth_records, root_addl_records])
    print(f"RTT: {root_rtt} ms")
    #print(f"TLD IP: {tld_ip_string}")

    #-------------TLD-----------

    packet, q_name = build_dns_packet(domain)

    print("--------------------------------------------")
    print(f"Querying {tld_ip_string} for {domain}")
    print("--------------------------------------------")
    response, tld_rtt = send_dns_packet(packet, tld_ip_string)
    transaction_id, flags, question_count, answer_count, authority_count, additional_rr_count = struct.unpack("!HHHHHH", response[:12])
    offset = 12 + len(q_name) + 4 

    tld_auth_records, offset = parse_dns_records(response, offset, authority_count) # No IP in the authority section
    tld_addl_records, offset = parse_dns_records(response, offset, additional_rr_count)

    print_records([tld_auth_records, tld_addl_records])
    print(f"RTT: {tld_rtt} ms")

    if "A" not in tld_addl_records and "NS" in tld_auth_records:
        #recursively query the NS domain
        # ns0229.secondary.cloudflare.com
        ns_ip = get_final_ip(tld_auth_records["NS"][0])
        packet, q_name = build_dns_packet(domain)
        print("--------------------------------------------")
        print(f"Querying {ns_ip} for {domain}")
        print("--------------------------------------------")
        response, auth_rtt = send_dns_packet(packet, ns_ip)
        transaction_id, flags, question_count, answer_count, authority_count, additional_rr_count = struct.unpack("!HHHHHH", response[:12])
        offset = 12 + len(q_name) + 4 
        auth_ans_records, offset = parse_dns_records(response, offset, answer_count)
        print_records([auth_ans_records])
        print(f"RTT: {auth_rtt} ms")
        final_ip = auth_ans_records["A"][0]
        return final_ip

    auth_ip_string = tld_addl_records["A"][0]

    #-------------AUTHORITATIVE-----------

    print("--------------------------------------------")
    print(f"Querying {auth_ip_string} for {domain}")
    print("--------------------------------------------")
    #print(records)
    packet, q_name = build_dns_packet(domain)
    response, auth_rtt = send_dns_packet(packet, auth_ip_string)
    transaction_id, flags, question_count, answer_count, authority_count, additional_rr_count = struct.unpack("!HHHHHH", response[:12])
    offset = 12 + len(q_name) + 4 

    auth_ans_records, offset = parse_dns_records(response, offset, answer_count)

    print_records([auth_ans_records])
    print(f"RTT: {auth_rtt} ms")


    final_ip_string = auth_ans_records["A"][0]
    return final_ip_string

def solve(domain):
    final_ip = get_final_ip(domain)
    http_response, http_rtt = send_http_request(final_ip, domain)
    http_lines = http_response.decode().split("\r\n")
    status_line = http_lines[0]
    status_code = status_line.split(" ")[1]
    print(status_code)
    print(f"RTT: {http_rtt} ms")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Incorrect number of args. Expected ./DNS_client_AtticusWong_RichardZhang.py <domain>")
        sys.exit(1)
    domain = sys.argv[1]
    solve(domain)

