import socket

HOST = "127.0.0.1"
PORT = 55000

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((HOST, PORT))
server.listen(1)

print(f"Server listening on {HOST}:{PORT}")

conn, addr = server.accept()
print(f"Connected by {addr}")

while True:
    data = conn.recv(1024).decode()
    if not data or data.lower() == "exit":
        print("Connection closed by client.")
        break
    
    print(f"Received from client: {data}")
    conn.send(f"Echo: {data}".encode())

conn.close()
server.close()
print("Server shutdown.")