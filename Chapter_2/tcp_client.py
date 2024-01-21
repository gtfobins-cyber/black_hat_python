import socket

# Most basic, most common client ill ever write.
# Assumption 1 - Will always succeed.
# Assumption 2 - Send data first.
# Assumption 3 - Will always reply.

target_host = "127.0.0.1"
target_port = 9998

# Creates a socket object
# Standard Ipv4
# SOCK_STREAM = TCP client
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to the client
client.connect((target_host, target_port))

# Send some data
# Sent as bytes


# client.send(b"GET / HTTP/1.1\r\nHost: httpbin.org\r\n\r\n")
client.sendto(b"Hello from the other terminal.", (target_host,target_port))

# Recieve some data
response = client.recv(4096)

print(response.decode())
client.close()