import random
import socket

# Predefined prime number (p) and base (g)
p = 23  # Same prime as client
g = 5   # Same generator as client

# server generates private key and computes public key
private_key_server = random.randint(1, p - 1)
public_key_server = pow(g, private_key_server, p)
print(f"Server Private Key: {private_key_server}")
print(f"Server Public Key: {public_key_server}")

# Step 1: Set up server to receive client's public key
server_address = ('0.0.0.0', 65443)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(server_address)
sock.listen(1)

print("Waiting for Client to connect...")
connection, client_address = sock.accept()
try:
    # Step 2: Receive client's public key
    public_key_client = int(connection.recv(1024).decode())
    print(f"Server received Client's Public Key: {public_key_client}")

    # Step 3: Send server's public key to client
    connection.sendall(str(public_key_server).encode())
    print("Server's Public Key sent to Client")

    # Step 4: Compute shared secret
    shared_secret_server = pow(public_key_client, private_key_server, p)
    print(f"Server Shared Secret: {shared_secret_server}")
finally:
    connection.close()

