import socket
import os

# Difference between Windows and Linux is
# that Windows will allow sniffing of all
# incoming packets regardless of the protocol.

# This is the host to listen on.
HOST = '192.168.0.3'


    # Creates raw socket, bin to public interface

if os.name == 'nt':
    socket_protocol = socket.IPPROTO_IP
else:
    socket_protocol = socket.IPPROTO_ICMP


sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
sniffer.bind((HOST, 0))

# Includes the IP header in the capture.

sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

if os.name == 'nt':
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

# Reads one packet
print(sniffer.recvfrom(65565))

# If you are on Windows, turn off promiscuous mode.

if os.name == 'nt':
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
