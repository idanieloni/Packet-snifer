import socket
import os, sys, time
import struct
import threading
from ipaddress import *
from ctypes import *
import netifaces as ni

TAB ='\t'
TAB2 ='\t\t'
TAB3 ='\t\t\t'
TAB4 ='\t\t\t\t'
NL ='\n'

def main():
    # subnet to target
    target_subnet = input('Enter target subnet (CIDR): ') or "192.168.1.0/24"

    # magic we'll check ICMP responses for
    target_message = input('Enter target message: ') or "Test message"

    host = input('Enter host address: ') or ni.ifaddresses('enp1s0')[ni.AF_INET][0]['addr']
    print("Listening on", host, "...")
    s = Scanner(host, target_subnet, target_message)
    #time.sleep(5)
    try:
        t = threading.Thread(target=s.udp_sender)
        t.start()
    finally:
        s.sniff()

class IP:
    def __init__(self, buff=None):
        header = struct.unpack('<BBHHHBBH4s4s', buff)
        self.ver = header[0] >> 4
        self.ihl = header[0] & 0xF
        self.tos = header[1]
        self.len = header[2]
        self.id = header[3]
        self.offset = header[4]
        self.ttl = header[5]
        self.protocol_num = header[6]
        self.sum = header[7]
        self.src = header[8]
        self.dst = header[9]
        

        # human readable IP addresses
        self.src_address = ip_address(self.src)
        self.dst_address = ip_address(self.dst)

         # map protocol constants to their names
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
       
        # human readable protocol
        try:
            self.protocol = self.protocol_map[self.protocol_num]
            
        
        except IndexError:
            print('%s No protocol for %s' % (e, self.protocol_num))
            self.protocol = str(self.protocol_num)


class ICMP(Structure):
    def __init__(self, buff):
        header = struct.unpack('<BBHHH', buff)
        self.type = header[0]
        self.code = header[1]
        self.sum = header[2]
        self.id = header[3]
        self.seq = header[4]


class Scanner:
    def __init__(self, host, target_subnet, target_message):
        self.host = host
        self.target_subnet = target_subnet
        self.target_message = target_message
        
    # create a raw socket and bind it to the public interface
        if os.name == "nt":
            socket_protocol = socket.IPPROTO_IP
        else:
            socket_protocol = socket.IPPROTO_ICMP
            
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
        self.sock.bind((host, 0))
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        if os.name == "nt":
                self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        # if we're on Windows we need to send some ioctl
        # to setup promiscuous mode
    
    def udp_sender(self):
        target_message = self.target_message
        target_subnet = self.target_subnet
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            try:
                for ip in ip_network(target_subnet).hosts():
                    sender.sendto(target_message.encode('utf-8'), (str(ip), 65212))
            except:
                socket.error()
                print("error sending to", str(ip) )
            
    def sniff(self):
        target_message = self.target_message
        target_subnet = self.target_subnet
        socket = self.sock
        
        hosts_up = set([f'{str(self.host)} *'])
        
        hosts = []
        host_count = 0 
        host_count_inc = 0
        
        res_hosts=[]
        res_host_count = 0 
        
        nonres_hosts = []
        nonres_host_count = 0
        
        nonsubnet_hosts = []
        nonsubnet_host_count = 0
        
        res_noport_hosts = []
        res_noport_host_count = 0
        
        host_lists = [res_hosts, res_noport_hosts, nonsubnet_hosts, nonres_hosts]
        host_lists_counts = [res_host_count, res_noport_host_count, nonsubnet_host_count, nonres_host_count]
        def updateHosts(host_lists, host_list, host, host_lists_counts, host_list_count):
            for item in host_lists:
                if item is host_list:
                    item.append(host)
                else:
                    item.pop(host)
                    
            for item in host_lists_counts:
                if item is host_list_count:
                    item[0] += 1
                else:
                    if item[0] < 1:
                        pass
                    else:
                        item[0] -= 1
                    
            return [host_lists, host_lists_counts]
        
        reacheable = False
        check_reacheable = False
        try:
            while True:
                # read in a single packet
                raw_buffer = socket.recvfrom(65535)[0]

                ip_header = IP(raw_buffer[:20])
                
                # if it's ICMP we want it
                
                if ip_header.protocol == "ICMP":    
                    offset = ip_header.ihl * 4
                    buf = raw_buffer[offset:offset + 8]
                    # create our ICMP structure
                    icmp_header = ICMP(buf)
                    
                    if ip_address(ip_header.src_address) in ip_network(target_subnet):
                        if (str(ip_header.src_address)) not in hosts:
                            hosts.append(str(ip_header.src_address))
                            host_count +=1 
                            print (hosts)
                                
                        if icmp_header.code == 0:
                            reacheable = False
                            print(f' Network {target_subnet} is unreachable')
                            updates = updateHosts(host_lists, res_hosts ,(str(ip_header.src_address)))
                            host_lists = updates[0]
                            host_lists_counts = updates[1]
                            
                        elif icmp_header.type == 1:
                            reacheable = False
                            print(f' Host {ip_header.src_address} is unreachable')
                            updates = updateHosts(host_lists, nonres_hosts,(str(ip_header.src_address)), host_lists_counts, nonres_host_count)
                            host_lists = updates[0]
                            host_lists_counts = updates[1]                                
                            host_count_inc += 1
                            print(updates)
                            
                        elif icmp_header.code == 3 and icmp_header.type == 3:
                            if raw_buffer[len(raw_buffer)
                            - len(target_message):] == target_message:
                                print(f'!Host {ip_header.src_address} is up, but port is unreachable')
                                updates = updateHosts(host_lists, res_noport_hosts ,(str(ip_header.src_address)), host_lists_counts, res_noport_host_count)
                                host_lists = updates[0]
                                host_lists_counts = updates[1]                                
                                host_count_inc += 1
                                
                        elif icmp_header.code == 0:
                            if (str(ip_header.src_address)) not in res_hosts:
                                print(f' Host {ip_header.src_address} is now reachable')
                                update = updateHosts(host_lists, res_hosts ,(str(ip_header.src_address)), host_lists_counts, res_host_count)
                                host_lists = updates[0]
                                host_lists_counts = updates[1]                                
                                host_count_inc += 1
                            
                                        
                    else:
                        print(f'Host\"{ip_header.src_address}\" is out of subnet \"{target_subnet}\"')
                        updates = updateHosts(host_lists, nonsubnet_hosts ,(str(ip_header.src_address)), host_lists_counts, nonsubnet_host_count)
                        host_lists = updates[0]
                        host_lists_counts = updates[1]                                
                        host_count_inc += 1
                        
                    if host_count < host_count_inc:
                        print(NL)
                        print(f'! Number of hosts: {host_count}')
                        print(f'! Number of resposive hosts: {res_host_count}')
                        print(f'! Number of non-responsive hosts: {nonres_host_count}')
                        print(f'! Number of hosts with unreachable ports: {res_noport_host_count}')
                        host_count_inc = host_count
                        
                    print(NL + f'Protocol: {ip_header.protocol}' + NL + TAB + f'Source : {ip_header.src_address}, Destination : {ip_header.dst_address}')
                     # calculate where our ICMP packet starts
                    
                    print(TAB + f'Version: {ip_header.ver}, Header Length: {ip_header.ihl},' + 
                                f'TTL: {ip_header.ttl}, Type: {icmp_header.type}, Code: {icmp_header.code}'
                        )

                else:
                    print(NL + f'Protocol: {ip_header.protocol}' + NL + TAB + f'Source : {ip_header.src_address}, Destination : {ip_header.dst_address}')

        # handle CTRL-C
        except KeyboardInterrupt:
            # if we're on Windows turn off promiscuous mode
            if os.name == "nt":
                socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)


        
if __name__ == "__main__":
    main()