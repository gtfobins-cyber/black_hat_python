import paramiko

def ssh_command(ip, port, user, passwd, cmd):

    # Parameters used to make the connection.
    # It's advised to use keys.
    # Sets the policy to use AutoAddPolicy() which auto adds host keys.

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, port=port, username=user, password=passwd)

    # Using the exec_command on the client object.
    # _, means the value is not important.
    # 3 channels. Input, Output and Errors.
    # If output not empty, print line by line.

    _, stdout, stderr = client.exec_command(cmd)
    output = stdout.readlines() + stderr.readlines()
    if output:
        print("--- Output ---")
        for line in output:
            print(line.strip())

if __name__ == "__main__":
    
    # getpass gets username and password from the enviroment.

    import getpass
    
    print("----- Building SSH Client -----")
    user = input("Username: ")
    password = getpass.getpass()

    ip = input("Enter server IP: ")
    port = input("Enter port: ")
    cmd = input("Enter command: ")
    
    ssh_command(ip, port, user, password, cmd)