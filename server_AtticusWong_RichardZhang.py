import socket

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8005

if __name__ == '__main__':
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


    # server socket
    s.bind((SERVER_HOST, SERVER_PORT))
    s.listen(2)
    while True:
        # accepts from the proxy
        (clientsocket, address) = s.accept()
        print ("connection found!")
        data = clientsocket.recv(1024).decode()
        ans = ""

        if len(data) != 4:
            clientsocket.send("Message sent must be 4 characters!".encode())
            print("Message sent must be 4 characters!")
        elif data == "ping":
            print("pong")
            ans = "pong"
        elif data == "pong":
            print("ping")
            ans = "ping"
        else:
            print(data[::-1])
            ans = data[::-1]
        
        clientsocket.send(ans.encode())
