from ctypes import *
import socket
import struct

# This code snippet defines a new class, IP that can read a packet 
# and parse the header section into its seperate fields.

# Creating a fields structure to define each part of the IP.
# Mapping C data types to the IP header.

# IP inherits from ctypes module Structure class.
# Must specify a '_fields_' structure before creating.
# This uses the '__new__' method.

class IP(Structure):
    _fields_ = [
        ("ihl",             c_ubyte,    4),     # 4 bit unsigned char
        ("version",         c_ubyte,    4),     # 4 bit unsigned char
        ("tos",             c_ubyte,    8),     # 1 byte char
        ("len",             c_ushort,   16),    # 2 byte unsigned short
        ("id",              c_ushort,   16),    # 2 byte unsigned short
        ("offset",          c_ushort,   16),    # 2 byte unsigned short
        ("id",              c_ubyte,    8),     # 1 byte char
        ("protocol_num",    c_ubyte,    8),     # 1 byte char
        ("sum",             c_ushort,   16),    # 2 byte unsigned short
        ("src",             c_uint32,   32),    # 4 byte unsigned char
        ("dst",             c_uint32,   32),    # 4 byte unsigned char
]

# This returns object of the class.
# Passes to the '__init__' method.

def __new__(self, socket_buffer=None):
    return self.from_buffer_copy(socket_buffer)

def __init__(self, socket_buffer=None):

    # Human readable IP addresses
    self.src_address = socket.inet_ntoa(struct.pack("<L",self.src))
    self.dst_address = socket.inet_ntoa(struct.pack("<L",self.dst))