from services import *
from ipv4functions import *

def main():
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, addr = connection.recvfrom(65536)
        dest_phys_addr, src_phys_addr, e_proto, data = e_frame(raw_data)
        print('\nHost:', socket.gethostname())
        print('Ethernet Frame:')
        print(TAB + 'Dest: {}, Src: {}, Proto: {}, '.format(dest_phys_addr, src_phys_addr, e_proto)+
         'Service:', (services[e_proto]) if e_proto in services else 'Unknown Service Port')
        if e_proto == 8:
            (vers, header_len, ttl, proto, src, target, data) =  ipv4_pkt(data)
            print(TAB  + 'IPv4 PACKET: ')
            print(TAB2 + f'Version: {vers}, Header Length: {header_len}, Ttl: {ttl}')
            print(TAB3 + f'Protocol: {proto}, Source: {src}, Target: {target}')
            print(TAB2 + 'Data:', str(data, 'ascii').split(',' '\n'))

            
        elif e_proto == 1:
            icmp_type, code, checksum, data = icmp_pkt(data)
            print(TAB  + 'ICMP PACKET: ')
            print(TAB2 + f'Type: {icmp_type}, Code: {code}, Checksum:{checksum}')
            print(TAB2 + f'Data: {data}')

            
        elif e_proto == 6:
            src_p, dst_p, seq, ack, flg_urg, flg_ack, flg_psh, flg_rst, flg_syn, flg_fin, data = tcp_seg(data)
            print(TAB  + 'TCP Segment: ')
            print(TAB2 + f'Source Port: {src_p}, Destination Port: {dst_p}, ')
            print(TAB2 + f'Sequence: {seq}, Acknowledge: {ack}')
            print(TAB2 + f'FLAGS: ')
            print(TAB3 + f'URG: {urg}, ACK: {ack}, PSH: {psh}, SYN: {syn}, FIN: {fin}')
            print(TAB2 + f'Data: {data}')

            
if __name__ == '__main__':
    main()