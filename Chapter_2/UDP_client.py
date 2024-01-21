import socket

target_host = "127.0.0.1"
target_port = 9998

# Creates a socket object
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Send some data
client.sendto(b"Sending my own packet.",(target_host,target_port))

# Recieve some data
data, addr = client.recvfrom(4096)

print(data, addr)

print(data.decode())
client.close()

# Open another terminal and type nc -ul 127.0.0.1 -p 9997
# and this command will show you the recieved data.