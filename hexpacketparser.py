import struct
import binascii

def dict_to_html_table(title, d):
    """Convert a dictionary to an HTML table with a header title."""
    html = f"<h2>{title}</h2>"
    html += "<table border='1' style='border-collapse: collapse;'>"
    for key, value in d.items():
        html += f"<tr><th style='padding: 4px; text-align: left;'>{key}</th>"
        html += f"<td style='padding: 4px;'>{value}</td></tr>"
    html += "</table><br>"
    return html

def parse_ethernet_header(data):
    """
    Parse the Ethernet header. If this contains a VLAN tag (0x8100),
    we grab that as well. We'll return a dictionary with either
    EtherType or VLAN info, along with the remainder of the payload.
    """
    if len(data) < 14:
        raise ValueError("Data too short to contain an Ethernet header.")
    
    # Unpack base Ethernet header
    dest_mac, src_mac, eth_type = struct.unpack('!6s6sH', data[:14])
    dest_mac = binascii.hexlify(dest_mac).decode()
    src_mac = binascii.hexlify(src_mac).decode()
    
    # Format MACs nicely
    dest_mac_str = ':'.join(dest_mac[i:i+2] for i in range(0, 12, 2))
    src_mac_str = ':'.join(src_mac[i:i+2] for i in range(0, 12, 2))
    
    eth_info = {
        'Destination MAC': dest_mac_str,
        'Source MAC': src_mac_str,
        'EtherType': hex(eth_type),
        'Payload': data[14:]
    }
    
    # Check for VLAN tag (EtherType 0x8100)
    # If VLAN tagged, next 4 bytes contain the VLAN tag and the next EtherType.
    if eth_type == 0x8100 and len(data) >= 18:
        vlan_tag, inner_type = struct.unpack('!HH', data[14:18])
        eth_info['VLAN Tag'] = vlan_tag & 0x0FFF  # lower 12 bits are VLAN ID
        eth_info['VLAN Priority'] = (vlan_tag >> 13) & 0x7
        eth_info['EtherType'] = hex(inner_type)
        eth_info['Payload'] = data[18:]
    
    return eth_info

def parse_ipv4_header(data):
    """
    Parse an IPv4 header in detail:
      - Version
      - IHL (header length)
      - DSCP/ECN
      - Total Length
      - Identification
      - Flags / Fragment Offset
      - TTL
      - Protocol
      - Header Checksum
      - Source IP
      - Destination IP
      - Remaining payload
    """
    if len(data) < 20:
        raise ValueError("Data too short to contain an IPv4 header.")
    
    # Byte 0: version and IHL
    version_ihl = data[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 0xF) * 4  # IP Header length is in 32-bit words
    
    # Byte 1: DSCP/ECN
    dscp_ecn = data[1]
    
    # Bytes 2-3: total length
    total_length = struct.unpack('!H', data[2:4])[0]
    
    # Bytes 4-5: Identification
    identification = struct.unpack('!H', data[4:6])[0]
    
    # Bytes 6-7: flags / fragment offset
    flags_frag = struct.unpack('!H', data[6:8])[0]
    flags = (flags_frag >> 13) & 0x7
    fragment_offset = flags_frag & 0x1FFF
    
    # Byte 8: TTL
    ttl = data[8]
    
    # Byte 9: Protocol
    protocol = data[9]
    
    # Bytes 10-11: Header checksum
    header_checksum = struct.unpack('!H', data[10:12])[0]
    
    # Bytes 12-15: Source IP
    src_ip_bytes = data[12:16]
    src_ip = '.'.join(map(str, src_ip_bytes))
    
    # Bytes 16-19: Destination IP
    dest_ip_bytes = data[16:20]
    dest_ip = '.'.join(map(str, dest_ip_bytes))
    
    # The rest is the options (if any) + data
    payload = data[ihl:]
    
    return {
        'Version': version,
        'IHL': ihl,
        'DSCP_ECN': dscp_ecn,
        'Total Length': total_length,
        'Identification': identification,
        'Flags': flags,
        'Fragment Offset': fragment_offset,
        'TTL': ttl,
        'Protocol': protocol,
        'Header Checksum': header_checksum,
        'Source IP': src_ip,
        'Destination IP': dest_ip,
        'Payload': payload
    }

def parse_tcp_header(data):
    """
    Parse more of the TCP header:
      - Source Port
      - Destination Port
      - Sequence Number
      - Acknowledgment Number
      - Data Offset
      - Flags
      - Window
      - Checksum
      - Urgent Pointer
      - Remaining Payload
    """
    if len(data) < 20:
        raise ValueError("Data too short to contain a minimal TCP header.")
    
    (src_port, dest_port,
     seq_num, ack_num,
     offset_reserved_flags,
     window) = struct.unpack('!HHLLHH', data[:14])
    
    data_offset = (offset_reserved_flags >> 12) & 0xF
    tcp_header_length = data_offset * 4
    
    # Lower 12 bits are flags
    flags = offset_reserved_flags & 0xFFF
    
    # The next 2 bytes after window are checksum, urgent pointer
    checksum, urgent_ptr = struct.unpack('!HH', data[14:18])
    
    # The rest is options (if any) plus data
    remaining_payload = data[tcp_header_length:]
    
    return {
        'Source Port': src_port,
        'Destination Port': dest_port,
        'Sequence Number': seq_num,
        'Acknowledgment Number': ack_num,
        'Data Offset': data_offset,
        'Flags': flags,
        'Window': window,
        'Checksum': checksum,
        'Urgent Pointer': urgent_ptr,
        'Payload': remaining_payload
    }

def parse_udp_header(data):
    """
    Parse the UDP header:
      - Source Port
      - Destination Port
      - Length
      - Checksum
      - Remaining Payload
    """
    if len(data) < 8:
        raise ValueError("Data too short to contain a minimal UDP header.")
    
    src_port, dest_port, length, checksum = struct.unpack('!HHHH', data[:8])
    payload = data[8:]
    
    return {
        'Source Port': src_port,
        'Destination Port': dest_port,
        'Length': length,
        'Checksum': checksum,
        'Payload': payload
    }

def parse_icmp_header(data):
    """
    Parse a basic ICMP header:
      - Type
      - Code
      - Checksum
      - Rest of Header (varies by ICMP type)
      - Remaining Payload
    """
    if len(data) < 4:
        raise ValueError("Data too short to contain an ICMP header.")
    
    icmp_type, icmp_code, icmp_checksum = struct.unpack('!BBH', data[:4])
    payload = data[4:]
    
    return {
        'Type': icmp_type,
        'Code': icmp_code,
        'Checksum': icmp_checksum,
        'Payload': payload
    }

def parse_packet(hex_data):
    """
    Top-level parser that:
      1. Converts hex to raw bytes
      2. Parses Ethernet (and possibly VLAN) header
      3. If IPv4, parse IPv4 header
      4. Based on protocol, parse TCP, UDP, or ICMP
    Returns an HTML-formatted string.
    """
    html_output = "<html><body>"
    raw_data = binascii.unhexlify(hex_data)
    
    # Parse Ethernet header and add HTML
    eth_info = parse_ethernet_header(raw_data)
    html_output += dict_to_html_table("Ethernet Header", eth_info)
    
    # Check for IPv4 based on EtherType
    if eth_info['EtherType'] in ['0x800', '0x0800']:
        ip_info = parse_ipv4_header(eth_info['Payload'])
        html_output += dict_to_html_table("IPv4 Header", ip_info)
        
        proto = ip_info['Protocol']
        if proto == 6:  # TCP
            tcp_info = parse_tcp_header(ip_info['Payload'])
            html_output += dict_to_html_table("TCP Header", tcp_info)
        elif proto == 17:  # UDP
            udp_info = parse_udp_header(ip_info['Payload'])
            html_output += dict_to_html_table("UDP Header", udp_info)
        elif proto == 1:  # ICMP
            icmp_info = parse_icmp_header(ip_info['Payload'])
            html_output += dict_to_html_table("ICMP Header", icmp_info)
        else:
            html_output += f"<p>Unknown or unsupported IPv4 protocol: {proto}</p>"
    else:
        html_output += "<p>Not an IPv4 packet (or unsupported EtherType).</p>"
    
    html_output += "</body></html>"
    
    # Print the HTML output (or return it for further use)
    print(html_output)
    return html_output

# Example usage:
if __name__ == "__main__":
    # Replace with your desired hex packet.
    hex_packet = (
        "d843ae5be7d860de4457402808004500024013b2000027117576d8b50b19"
        "c0a8640e1ae1d0e2022cad0e0100c5065f1602d0d8ff774700100000bf0c"
        "22edffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "ffffffffffffffffffffffffffffffffffffffffffffffff"
    )
    parse_packet(hex_packet)
