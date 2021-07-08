import socket
import struct
import textwrap
import sys

INTERFACE_NAME = 'enp0s3'

def format_multi_line(string, size=80):
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([line for line in textwrap.wrap(string, size)])

def get_mac_addr(raw_mac_addr):
    byte_str = map('{:02x}'.format, raw_mac_addr)
    mac_addr = ':'.join(byte_str).upper()
    return mac_addr

def destruct_ethernet_header(raw_data):
    dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])

    dest_mac = get_mac_addr(dest)
    src_mac = get_mac_addr(src)
    data = raw_data[14:]

    return dest_mac, src_mac, prototype, data

def destruct_ipv4_header(raw_data):
    first_byte = raw_data[0]
    version = first_byte >> 4
    ihl = (first_byte & 0b1111) * 4

    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
    src = get_ip(src)
    target = get_ip(target)

    data = raw_data[ihl:]
    
    return first_byte, version, ihl, ttl, proto, src, target, data

def destruct_tcp_header(raw_data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack(
        '! H H L L H', raw_data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 0b100000) >> 5
    flag_ack = (offset_reserved_flags & 0b10000) >> 4
    flag_psh = (offset_reserved_flags & 0b1000) >> 3
    flag_rst = (offset_reserved_flags & 0b100) >> 2
    flag_syn = (offset_reserved_flags & 0b10) >> 1
    flag_fin = offset_reserved_flags & 1
    data = raw_data[offset:]
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data

def destruct_udp_header(raw_data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', raw_data[:8])
    data = raw_data[8:]
    return src_port, dest_port, size, data

def destruct_icmp_header(raw_data):
    packet_type, code, checksum = struct.unpack('! B B H', raw_data[:4])
    data = raw_data[4:]
    return packet_type, code, checksum, data

def destruct_arp_header(raw_data):
    hardware_type, protocol_type, hardware_size, protocol_size, opcode, src_mac, src_ip, dest_mac, dest_ip = struct.unpack('! H H B B H 6s 4s 6s 4s', raw_data[:28])

    src_mac = get_mac_addr(src_mac)
    src_ip = get_ip(src_ip)
    dest_mac = get_mac_addr(dest_mac)
    dest_ip = get_ip(dest_ip)

    data = raw_data[28:]
    
    return hardware_type, protocol_type, hardware_size, protocol_size, opcode, src_mac, src_ip, dest_mac, dest_ip, data

def decode_http(raw_data):
    try:
        data = raw_data.decode('utf-8')
    except:
        data = raw_data
    return data

def get_ip(addr):
    return '.'.join(map(str, addr))

def main():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    try:
        s.bind((INTERFACE_NAME, 0))
    except:
        print('Device interface not found')
        sys.exit()

    while True:
        raw_data, addr = s.recvfrom(65535)
        print('=================================')
        eth = destruct_ethernet_header(raw_data)

        print('Ethernet frame:')
        print('Destination Mac: {}, Source Mac: {}, EtherType: {}'.format(eth[0], eth[1], eth[2]))
        print('---------------------------------')

        if eth[2] == 0x0800:
            ipv4 = destruct_ipv4_header(eth[3])
            print('IPv4 header:')
            print('TTL: {}'.format(ipv4[1], ipv4[2], ipv4[3]))
            print('Source IP: {}, Target IP: {}, Protocol: {}'.format(ipv4[5], ipv4[6], ipv4[4]))
            print('---------------------------------')

            # TCP
            if ipv4[4] == 6:
                tcp = destruct_tcp_header(ipv4[7])
                print('TCP:')
                print('Source port: {}, Destination port: {}'.format(tcp[0], tcp[1]))
                print('Flags:')
                print('URG: {}, ACK: {}, PSH: {}'.format(tcp[4], tcp[5], tcp[6]))
                print('RST: {}, SYN: {}, FIN: {}'.format(tcp[7], tcp[8], tcp[9]))
                print('---------------------------------')

                if len(tcp[10]) > 0:
                    # HTTP
                    if tcp[0] == 80 or tcp[1] == 80:
                        print('HTTP data:')
                        try:
                            http = http(tcp[10])
                            http_info = str(http[10]).split('\n')
                            for line in http_info:
                                print('' + str(line))
                        except:
                            print(format_multi_line(tcp[10]))
                    else:
                        print('TCP Data:')
                        print(format_multi_line(tcp[10]))

            # ICMP
            elif ipv4[4] == 1:
                icmp = destruct_icmp_header(ipv4[7])
                print('ICMP:')
                print('Type: {}, Code: {}, Checksum: {},'.format(icmp[0], icmp[1], icmp[2]))
                print('---------------------------------')
                print('ICMP data:')
                print(format_multi_line(icmp[3]))

            # UDP
            elif ipv4[4] == 17:
                udp = destruct_udp_header(ipv4[7])
                print('UDP:')
                print('Source Port: {}, Destination Port: {}, Length: {}'.format(udp[0], udp[1], udp[2]))

            # Other IPv4
            else:
                print('Other IPv4 data:')
                print(format_multi_line(ipv4[7]))
        
        # ARP
        elif eth[2] == 0x0806:
            arp = destruct_arp_header(eth[3])
            print('ARP:')
            print('Hardware type: {}, Protocol type: {}'.format(arp[0], arp[1]))
            print('Hardware size: {}, Protocol size: {}'.format(arp[2], arp[3]))
            print('Opcode: {}'.format(arp[4]))
            print('Source Mac: {}, Source IP: {}'.format(arp[5], arp[6]))
            print('Dest Mac: {}, Dest IP: {}'.format(arp[7], arp[8]))
            print('---------------------------------')

        else:
            print('Ethernet data:')
            print(format_multi_line(eth[3]))
            
        print('=================================')


main()