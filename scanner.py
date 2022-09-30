import socket
import os, sys, time
import struct
import threading
from ipaddress import *
from ctypes import *
import netifaces as ni

# subnet to target
tgt_subnet = "192.168.1.0/27"

# magic we'll check ICMP responses for
tgt_message = "Test String"

class IP(Structure):
    _fields_ = [
        ("ihl", c_ubyte, 4),
        ("version", c_ubyte, 4),
        ("tos", c_ubyte),
        ("len", c_ushort),
        ("id", c_ushort),
        ("offset", c_ushort),
        ("ttl", c_ubyte),
        ("protocol_num", c_ubyte),
        ("sum", c_ushort),
        ("src", c_uint32),
        ("dst", c_uint32)
    ]

    def __new__(cls, socket_buffer=None):
        return cls.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        self.socket_buffer = socket_buffer

        # map protocol constants to their names
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}

        # human readable IP addresses
        self.src_address = socket.inet_ntoa(struct.pack("@I", self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("@I", self.dst))

        # human readable protocol
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except IndexError:
            self.protocol = str(self.protocol_num)


class ICMP(Structure):
    _fields_ = [
        ("type", c_ubyte),
        ("code", c_ubyte),
        ("checksum", c_ushort),
        ("unused", c_ushort),
        ("next_hop_mtu", c_ushort)
    ]

    def __new__(cls, socket_buffer):
        return cls.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer):
        self.socket_buffer = socket_buffer

def udp_sender():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        for ip in ip_network(tgt_subnet).hosts():
            sender.sendto(bytes(tgt_message, 'utf8'), (str(ip), 65212))

class Scanner:
    def __init__(self, host):
        self.host = host
        
        # create a raw socket and bind it to the public interface
        if os.name == "nt":
            socket_protocol = socket.IPPROTO_IP
        else:
            socket_protocol = socket.IPPROTO_ICMP

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
        self.socket.bind((host, 0))
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# if we're on Windows we need to send some ioctl
# to setup promiscuous mode
        if os.name == "nt":
            self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)  

    def sniff(self): 
        hosts_up = set([f'{str(self.host)} *'])
        try:
            while True:

                # read in a single packet
                raw_buffer = self.socket.recvfrom(65535)[0]

                # create an IP header from the first 20 bytes of the buffer
                ip_header = IP(raw_buffer[0:20])
                
                # if it's ICMP we want it
                if ip_header.protocol == "ICMP":
                    print("Protocol: %s %s -> %s" % (
                    ip_header.protocol,
                    ip_header.src_address,
                    ip_header.dst_address)
                    )
                    # calculate where our ICMP packet starts
                    offset = ip_header.ihl * 4
                    buf = raw_buffer[offset:offset + sizeof(ICMP)]
                    # create our ICMP structure
                    icmp_header = ICMP(buf)

                    print("ICMP -> Type: %d Code: %d" % (
                        icmp_header.type,
                        icmp_header.code)
                        )
                    # now check for the TYPE 3 and CODE 3 which indicates
                    # a host is up but no port available to talk to           
                    if icmp_header.code == 3 and icmp_header.type == 3:
                        # check to make sure we are receiving the response 
                        # that lands in our subnet
                        if ip_address(ip_header.src_address) in IPv4Network(tgt_subnet):
                            # test for our magic message
                            if raw_buffer[len(raw_buffer)
                            - len(tgt_message):] == bytes(tgt_message, 'utf8'):
                                tgt = str(ip_header.src_address)
                                if tgt != self.host and tgt not in hosts_up:
                                    hosts_up.add(str(ip_header.src_address))
                                    print(f'Host Up: {tgt}')
                
        # handle CTRL-C
        except KeyboardInterrupt:
            # if we're on Windows turn off promiscuous mode
            if os.name == "nt":
                self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            print('\nUser interrupted.')
            if hosts_up:
                print(f'\n\nSummary: Hosts up on {tgt_subnet}')
            for host in sorted(hosts_up):
                print(f'{host}')
            print('')
            sys.exit()
if __name__ == '__main__':
    if len(sys.argv) == 2:
        host = sys.argv[1]
        print("Listeing on", host, "...")
    else:
        host = host = ni.ifaddresses('enp1s0')[ni.AF_INET][0]['addr']
        print("Listeing on", host)
    s = Scanner(host)
    time.sleep(5)
    t = threading.Thread(target=udp_sender)
    t.start()
    s.sniff()