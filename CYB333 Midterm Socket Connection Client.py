import socket

HOST = "127.0.0.1"
PORT = 55000

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    client.connect((HOST, PORT))
    print(f"Connected to server at {HOST}:{PORT}")

    while True:
        message = input("Enter message to send (type 'exit' to quit): ")
        client.send(message.encode())
        
        if message.lower() == "exit":
            print("Exiting the client.")
            break
        
        response = client.recv(1024).decode()
        print(f"Received from server: {response}")

except ConnectionRefusedError:
    print("ERROR: Could not reach the server.")

except Exception as e:
    print(f"An error occurred: {e}")

finally:
    client.close()
    print("Client shutdown.")