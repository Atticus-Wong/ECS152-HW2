import socket


SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8005

PROXY_SERVER_PORT = 8004


# sends data to server on port 8005
# receives data from server on port 8004

# has to 
whitelist = [

]
if __name__ == '__main__':
    # 
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


    # proxy server socket
    s.bind((SERVER_HOST, PROXY_SERVER_PORT))
    s.listen(2)
    while True:
        # receive from the client, and open a TCP connection to send the data to the server

        (clientsocket, address) = s.accept()
        print ("connection found!")
        data = clientsocket.recv(1024).decode()
        print(data)

        # opens a port to the server and sends data to the server
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        server.connect((SERVER_HOST, SERVER_PORT))
        server.sendall(data.encode('utf-8'))

        # receive data from server
        new_data = server.recv(1024).decode()
        print(f"new_data: {new_data}")

        clientsocket.sendall(new_data.encode('utf-8'))
