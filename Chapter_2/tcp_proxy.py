import sys
import socket
import threading

# Generates a string of Unicode.
# Used as a filter to map for .translate
# This makes a convertion chart.
# Matches the length of the respresentation (printable characters).
# e.g newline or a tab (have longer 'repr' than 3) they will be .
HEX_FILTER = ''.join([(len(repr(chr(i))) == 3) and chr(i) or '.' for i in range(256)])

# Function for converting strings into hex.
def hexdump(src, length=10, show=True):
    

    if isinstance(src, bytes):
        src = src.decode()
    
    # List to store the lines of hex dump.
    results = list()

    # Loop the input string in chunks of length.
    # Start - Finish - Measurement.
    # Breaks the string into chunks.
    for i in range(0, len(src), length):

        # This then creates a word.
        # The string of the 'src'
        # loop i, steps of the length (16).
        word = str(src[i:i+length])

        # Print the translated string (word).
        # Translates all the printable chunks/chars (3).
        # All others that arent, will be a period .
        printable = word.translate(HEX_FILTER)
        
        # Returns the Unicode version, 2 digit, x=lower, X=upper 
        # Converts each character to the Unicode code point in 4-digit hex format.
        # hexwidth represents the 4-digit hex plus a space between each.
        hexa = ' '.join([f'{ord(c):04x}' for c in word])
        hexwidth = length*5

        # This is how we want it to look.
        # This appends a formatted string to the results list.
        # Left-aligns hexa
        # 'printable' is the string after translation.
        results.append(f'{i:02x}   {hexa:<{hexwidth}}   {printable}')
    
    # This is for the show option whether or not you want the
    # match of the filter (3) to be printed.
    if show:
        for line in results:
            print(line)
    else:
        return results
    
    # To receive connections.
def receive_from(connection):

    # Buffer to recieve the data.
    buffer = b""
    connection.settimeout(5)
    
    try:
        while True:
            # Recieve data until there isnt data or timeout.
            # Local or remote
            data = connection.recv(4096)
            if not data:
                break
            buffer += data
    except Exception as e:
        pass
    return buffer
    
def request_handler(buffer):
    # packet modifications here
    return buffer
    
def response_handler(buffer):
    # packet modifications here
    return buffer
    
# The handler connects to a remote host.

def proxy_handler(client_socket, remote_host, remote_port, receive_first):
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_socket.connect((remote_host, remote_port))

    # If 'receive_first' is True you recieve data first.    
    # The received data is printed with 'hexdump'.
    # Allows the proxy to initiate communication first or wait for the client to send first
    if receive_first:
        remote_buffer = receive_from(remote_socket)
        hexdump(remote_buffer)

    # The received data is processed by the handler.
    # If the processed data has a non-zero length, it is sent to the
    # client using send socket.
    remote_buffer = response_handler(remote_buffer)
    if len(remote_buffer):
        print("[<==] Sending %d bytes to localhost." % len(remote_buffer))
        client_socket.send(remote_buffer)

    # This is a mini proxy loop.
    # Runs continuously to recieve and send data.
    # 
    while True:

        local_buffer = receive_from(client_socket)
        if len(local_buffer):
            # For handling data received from the client.
            line = "[==>] received %d bytes from localhost." % len(local_buffer)
            print(line)
            hexdump(local_buffer)

            # Handles data sent to the remote host.
            local_buffer = request_handler(local_buffer)
            remote_socket.send(local_buffer)
            print("[==>] Sent to remote.")

            # Handles data received from the server.
            remote_buffer = receive_from(remote_socket)

        # Handles data sent to the client.
        if len(remote_buffer):
            print("[<==] received %d bytes from remote." % len(remote_buffer))
            hexdump(remote_buffer)

            remote_buffer = response_handler(remote_buffer)
            client_socket.send(remote_buffer)
            print("[<==] Sent to localhost.")
        
        # If there is no data at all from either buffers, break.
        if not len(local_buffer) or not len(remote_buffer):
            client_socket.close()
            remote_socket.close()
            print("[*] No more data. Closing connections.")
            break

# When server loop gets used it creates a new IPV4 socket.
# Tries to bind to the local port and address.
def server_loop(local_host, local_port, remote_host, remote_port, receive_first):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind((local_host, local_port))
    except Exception as e:
        print("Problem on binding: %r" % e)
        print("[!!] Failed to listen on %s:%d" % (local_host, local_port))
        print("[!!] Check for other listening sockets or correct permissions.")
        sys.exit(0)

    # Prints the listening message then starts to listen.
    print("[*] Listening on %s:%d" % (local_host, local_port))
    # Maximum number of connectioned allowed to be queued.
    server.listen(5)

    # This is to accept incoming connections.
    # Continuously accepts the connections.
    while True:
        client_socket, addr = server.accept()
        # Print out the local connection information.
        # Displays ip and port connected.
        line = "> received incoming connection from %s:%d" % (addr[0], addr[1])
        print(line)
        # Start a thread to talk to the remote host.
        # Creates a new thread and passes attributes.
        # This seperates the main server loop.
        proxy_thread = threading.Thread(target=proxy_handler, args=(client_socket, remote_host, remote_port, receive_from))
        proxy_thread.start()

def main():

    if len(sys.argv[1:]) != 5:
        print("Usage: ./proxy.py [localhost] [localport] [remoteserver] [remoteport]", end='')
        print("Example: ./proxy.py 127.0.0.1 21 192.168.0.3 21 True")

        sys.exit()
    
    local_host = sys.argv[1]
    local_port = int(sys.argv[2])

    remote_host = sys.argv[3]
    remote_port = int(sys.argv[4])

    receive_first = sys.argv[5]

    if "True" in receive_first:
        receive_first = True
    else:
        receive_first = False

    server_loop(local_host, local_port, remote_host, remote_port, receive_first)

if __name__ == "__main__":
    main()
    # print(hexdump("Python gets converted."))