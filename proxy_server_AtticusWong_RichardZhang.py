import socket
import json

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8005

PROXY_SERVER_PORT = 8004


# sends data to server on port 8005
# receives data from server on port 8004

# has to 
blocklist = [
    # "127.0.0.1",
    "192.168.0.1"
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
        raw_data = clientsocket.recv(1024).decode()
        data = json.loads(raw_data)

        print("----------------------------")
        print("Received from client:") 
        print("----------------------------")
        print("data = {")
        print(f"\"server_ip\": \"{data['server_ip']}\"")
        print(f"\"server_port\": \"{data['server_port']}\"")
        print(f"\"message\": \"{data['message']}\"")
        print("}")

        # logic for the ip blocklist here
        
        if f"{data['server_ip']}" in blocklist:
            clientsocket.sendall("Blocklist Error".encode('utf-8'))
        else:
            # opens a port to the server and sends data to the server
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            server.connect((SERVER_HOST, SERVER_PORT))
            server.sendall(data["message"].encode('utf-8'))
            print("----------------------------")
            print("Sent to server:") 
            print("----------------------------")
            print(f"\"{data['message']}\"")

            # receive data from server
            new_data = server.recv(1024).decode()
            print("----------------------------")
            print("Received from server:") 
            print("----------------------------")
            print(f"\"{new_data}\"")

            clientsocket.sendall(new_data.encode('utf-8'))

            print("----------------------------")
            print("Sent to client:") 
            print("----------------------------")
            print(f"\"{new_data}\"")
