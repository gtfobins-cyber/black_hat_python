import socket
import os
import struct
from ctypes import *
import time
from netaddr import IPNetwork, IPAddress
import threading

# This is the host to listen on.
# The host is my kali box.
# My Windows machine doesnt allow prom mode on the adapter.

# I want to change this to a prompt for an arguement.
# Functionality for Linux and Windows.

HOST = '192.168.0.3'
SUBNET = '192.168.0.0/16'
MAGIC_MSG = 'PythonRules!'

# String for the UDP Datagram.

def udp_sender(SUBNET, MAGIC_MSG):
    time.sleep(5)
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    for ip in IPNetwork(SUBNET):
        try:
            sender.sendto(MAGIC_MSG, ("%s" % ip, 65535))
        except:
            pass    

# Unpacking header fields.
# Using ctypes method instead of struct but using struct to pack/unpack.

class IP(Structure):
    _fields_ = [
        ("ihl", c_ubyte, 4),
        ("version", c_ubyte, 4),
        ("tos", c_ubyte),
        ("len", c_ushort),
        ("id", c_short),
        ("offset", c_ushort),
        ("ttl", c_ubyte),
        ("protocol_num", c_ubyte),
        ("sum", c_ubyte),
        ("src", c_uint),
        ("dst", c_uint),
    ]
    
    # Initializes new data into the structure given. This is how
    # we can predict the right or wrong packet with header length.

    def __new__(cls, socket_buffer=None):
        return cls.from_buffer_copy(socket_buffer)
    
    # Maps the specified protocol field to the right
    #  *constant* protocol number. These numbers won't change.

    def __init__(self, socket_buffer=None):

        # Maps the Transport Layer Protocols in the header.
        # If we never mapped nothing they would be represented by integers.

        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}

        # Human readable IP addresses
        # 32-bit packed binary to be converted.
        # The <L packs the binary string in little-endian *Linux systems use <L*
        
        # 'inet_ntoa' is a method used to convert the binary by
        # passing the binary string in. Which is the objects self
        # and taking the .src and .dst fields.

        self.src_address = socket.inet_ntoa(struct.pack("<L",self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("<L",self.dst))

        # Human readable IP addresses

        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)

# Adding ICMP functionality for ping data

class ICMP(Structure):
    _fields_ = [
        ("type", c_ubyte),
        ("code", c_ubyte),
        ("checksum", c_ushort),
        ("unused", c_ushort),
        ("next_hop_mtu", c_short),
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)
    
    def __init__(self, socket_buffer=None):
        pass

# I want to expand and add TCP and UDP.
# #2 on network is BGP, add it!

# Creates a new socket and binds it to the local interface.
# Sets which socket protocol is being detected.
# Windows uses 'nt' as an os name, NewTechnology acronym.

# IPPROTO_IP is windows check.
# IPPROTO_ICMP is Linux' check.

if os.name == 'nt':
    socket_protocol = socket.IPPROTO_IP
else:
    socket_protocol = socket.IPPROTO_ICMP

# Creating a socket saving it as sniffer.
# The socket binds to the address to be sniffed.
# Using 'setsockopt' you can specify options like 'include the header'.
# Raw sockets provide access to the data for like, parsing binary data.

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)

# 0 value just doesnt care about specific ports.
# HOST = Interface.

sniffer.bind((HOST, 0))
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# If this systems name is 'nt' then turn on promiscuous mode.
# Using 'ioctl' we can change the state of the socket with 'SIO_RCVALL'

if os.name == 'nt':
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

# Sending the packets into the subnet.

t = threading.Thread(target=udp_sender, args=(SUBNET, MAGIC_MSG))
t.start()

# One after the other the loop will continue
# to catch the packets and strip the header out.

try:
    while True:

        # Read in the packet and name it 'raw_buffer'.

        raw_buffer = sniffer.recvfrom(65565)[0]

        # Creates IP header from the first 20 bytes of the buffer.
        
        ip_header = IP(raw_buffer[0:20])

        # Print out the protocol that was detected and the hosts.
        
        print(f"Protocol: %s %s -> %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address))

        # Functionality for ping
        if ip_header.protocol == "ICMP":

            # If the Protocol maps to ICMP, offset the packet for buffer.

            offset = ip_header.ihl * 4

            # Calc size of buffer after offset
            # 'sizeof' calculates number of bytes on C type objects.

            ping_buffer = raw_buffer[offset:offset + sizeof(ICMP)]

            # Creating a ICMP structure with the buffer.

            ping_header = ICMP(ping_buffer)

            print(f"ICMP -> Type: %d Code: %d Checksum: %d" % (ping_header.type, ping_header.code, ping_header.checksum))

            if ping_header.code == 3 and ping_header.type == 3:
                if IPAddress(ip_header.src_address) in IPNetwork(SUBNET):
                    if raw_buffer[len(raw_buffer) - len(MAGIC_MSG):] == MAGIC_MSG:
                        print(f"The host is up.")
            

except KeyboardInterrupt:

    # If the loop is interupted by CTRL+C, then
    # use io control to switch the adapter state back.

    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)