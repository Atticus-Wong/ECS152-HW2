import socket
import sys

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8005

PROXY_SERVER_PORT = 8004


class Data:
    server_ip: str
    server_port: int
    message: str

if __name__ == '__main__':
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


    if not sys.argv[1:]:
        raise Exception("You forgot to add a message")

    m = str(sys.argv[1])
    if len(m) != 4:
        raise Exception("Message sent must be 4 characters!")

    data = {
        "server_ip": SERVER_HOST,
        "server_port": SERVER_PORT,
        "message": m
    }



    s.connect((SERVER_HOST, PROXY_SERVER_PORT))
    s.sendall(data["message"].encode('utf-8'))
    print("Sent:", data["message"])

    # receive response from the proxy
    proxy_message = s.recv(1024).decode()
    print(proxy_message)




