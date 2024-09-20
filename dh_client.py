import random
import socket

# Predefined prime number (p) and base (g)
p = 23  # Example small prime number
g = 5   # Primitive root modulo p

# client generates private key and computes public key
private_key_client = random.randint(1, p - 1)
public_key_client = pow(g, private_key_client, p)
print(f"Client Private Key: {private_key_client}")
print(f"Client Public Key: {public_key_client}")

# Step 1: Send client's public key to server using socket
server_address = ('192.168.66.148', 65443)  # server's address
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(server_address)
try:
    sock.sendall(str(public_key_client).encode())  # Send client's public key
    print("Client's Public Key sent to Server")

    # Step 2: Receive server's public key
    public_key_server = int(sock.recv(1024).decode())
    print(f"Client received Server's Public Key: {public_key_server}")

    # Step 3: Compute shared secret
    shared_secret_client = pow(public_key_server, private_key_client, p)
    print(f"Client Shared Secret: {shared_secret_client}")
finally:
    sock.close()

