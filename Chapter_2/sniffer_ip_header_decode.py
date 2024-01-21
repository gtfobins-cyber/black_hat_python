import socket
import os
import struct
from ctypes import *

# This is the host to listen on.
# The host is my kali box.
# My Windows machine doesnt allow prom mode on the adapter.

# I want to change this to a prompt for an arguement.
# Functionality for Linux and Windows.

HOST = '192.168.0.3'

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

# Creates a new socket and binds it to the local interface.
# Sets which socket protocol is being detected.
# Windows uses 'nt' as an os name, NewTechnology acronym.

if os.name == 'nt':
    socket_protocol = socket.IPPROTO_IP
else:
    socket_protocol = socket.IPPROTO_ICMP

# Creating a socket saving it as sniffer.
# The socket binds to the address to be sniffed.
# Using 'setsockopt' you can specify options like 'include the header'.
# Raw sockets provide access to the data.

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
sniffer.bind((HOST, 0))
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# If this systems name is 'nt' then turn on promiscuous mode.
# Using 'ioctl' we can change the state of the socket with 'SIO_RCVALL'

if os.name == 'nt':
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

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

except KeyboardInterrupt:

    # If the loop is interupted by CTRL+C, then
    # use io control to switch the adapter state back.

    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)