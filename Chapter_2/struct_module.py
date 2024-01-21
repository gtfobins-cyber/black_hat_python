import ipaddress
import struct

# This struct module provides format characters that you
# can use to specify the structure of the binary data.

class IP:
    def __init__(self, buff=None):

        # In this case, '<' specifies endianness of data.
        # Kali x64 is little-endian for example.
        
        # In little-endian the least significant byte is stored in
        # the lower address, the most significant byte in the
        # highest address.

        # B == 1-byte unsigned char
        # H == 2-byte unsigned short
        # s == A byte array that requires byte-width spec.
        # 4s == A 4-byte string that matches structure of IP header.

        header = struct.unpack("<BBHHHBBH4s4s", buff)
        self.ver = header[0] >> 4
        self.ihl = header [0] & 0xF

        self.tos = header[1]
        self.len = header [2]
        self.id = header[3]
        self.offset = header[4]
        self.ttl = header [5]
        self.protocol_num = header[6]
        self.sum = header[7]
        self.src = header[8]
        self.dst = header[9]

        # Human readable IP addresses

        self.src_address = ipaddress.ip_address(self.src)
        self.dst_address = ipaddress.ip_address(self.dst)

        # Map the protocol constants to their names.

        self.protocol_map = {1: "ICMP", 6: "TCP", 17:"UDP"}

class ICMP:
    def __init__(self, buff):
        header = struct.unpack("<BBHHH", buff)
        self.type = header[0]
        self.code = header[1]
        self.sum = header[2]
        self.id = header[3]
        self.seq = header[4]

        mypacket = IP(buff)
        print(f"{mypacket.src_address} -> {mypacket.dst_address}")

