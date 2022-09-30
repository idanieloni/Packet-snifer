import socket
import struct
import textwrap

TAB ='\t'
TAB2 ='\t\t'
TAB3 ='\t\t\t'
TAB4 ='\t\t\t\t'

def e_frame(data):
    dest_phys_addr, src_phys_addr, e_proto = struct.unpack('! 6s 6s H', data[:14])
    return format_phys_addr(dest_phys_addr), format_phys_addr(src_phys_addr), socket.htons(e_proto), data[14:]

def format_phys_addr(phys_addr):
    phys_addr_str = map('{:02x}'.format, phys_addr)
    return ':'.join(phys_addr_str).upper()

def ipv4_pkt(data):
    vers_header_len= data[0]
    vers = vers_header_len >> 4
    header_len =( vers_header_len & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return vers, header_len, ttl, proto, ipv4(src), ipv4(target), data[header_len:]

def ipv4(addr):
    return '.'.join(map(str, addr))

def icmp_pkt(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

def tcp_seg(data):
    (src_p, dest_p, seq, ack, off_res_flgs) = struct.unpack('! H H L L H', data[:14])
    off = (off_res_flgs >> 12) * 4
    flg_ack = (off_res_flgs & 16) >> 4
    flg_syn = (off_res_flgs & 2) >> 1
    flg_psh= (off_res_flgs & 8) >> 3
    flg_urg= (off_res_flgs & 32) >> 5
    flg_rst = (off_res_flgs & 4) >> 2
    flg_fin= off_res_flgs & 1
    return src_p, dst_p, seq, ack, flg_urg, flg_ack, flg_psh, flg_rst, flg_syn, flg_fin, data[off:]



def udp_seg(data):
    src_p, dst_p, size = struct.unpack('! H H 2X H', data)[:8]
    return src_p, dst_p, size, data[8:]
   

def printServiceOnPort():
    services = {}
    for i in range(0, 65536):
        service = None
        try:
            service = socket.getservbyport(i, 'tcp')
        except:
            pass
        if service is not None:
            services[i] = service
        try:
            service = socket.getservbyport(i, 'udp')
        except:
            pass
        if service is not None:
            services[i] = service
    return services

   