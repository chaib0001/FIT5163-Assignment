import socket
from srptools import SRPContext, SRPServerSession
import pickle
import sys

def recv_all(sock, n):
    """Helper function to receive exactly n bytes from a socket."""
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            raise Exception("Socket connection broken")
        data += packet
    return data

def print_and_flush(message):
    """Prints a message and flushes stdout."""
    print(message)
    sys.stdout.flush()

# Server configuration
HOST = '0.0.0.0'  # Listen on all interfaces
PORT = 65443

# User credentials (in a real application, store these securely)
USERNAME = 'user'
PASSWORD = 'secure_password'

print_and_flush("Starting SRP Server script.")

# Generate SRP context and get user data triplet
ctx = SRPContext(USERNAME, PASSWORD)
USERNAME, PASSWORD_VERIFIER, SALT_hex = ctx.get_user_data_triplet()

# Store the verifier and salt (in practice, store in a secure database)
user_data = {
    'username': USERNAME,
    'salt': SALT_hex,  # Keep as hex string
    'password_verifier': PASSWORD_VERIFIER,
}

# Start server
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind((HOST, PORT))
sock.listen(1)
print_and_flush("Waiting for Client to connect...")

conn, addr = sock.accept()
print_and_flush(f"Connected by {addr}")

try:
    # Step 1: Receive username and A from client
    data_length_bytes = recv_all(conn, 4)
    data_length = int.from_bytes(data_length_bytes, 'big')
    data = recv_all(conn, data_length)
    client_data = pickle.loads(data)
    username = client_data['username']
    A_hex = client_data['A']
    print_and_flush(f"Received username '{username}' and A from Client")
    print_and_flush(f"A_hex: {A_hex}")

    # Verify username
    if username != user_data['username']:
        raise Exception("Unknown user")

    # Step 2: Server computes B and sends salt and B to client
    context = SRPContext(username=username)
    server_session = SRPServerSession(context, password_verifier=user_data['password_verifier'])
    B_hex = server_session.public  # Already a hex string
    print_and_flush(f"B computed: {B_hex}")

    server_response = {
        'salt': user_data['salt'],
        'B': B_hex,
    }

    # Send server response
    response_data = pickle.dumps(server_response)
    data_length = len(response_data)
    conn.sendall(data_length.to_bytes(4, 'big'))
    conn.sendall(response_data)
    print_and_flush("Sent salt and B to Client")

    # Step 3: Receive M_client from client and verify
    data_length_bytes = recv_all(conn, 4)
    data_length = int.from_bytes(data_length_bytes, 'big')
    M_client_data = recv_all(conn, data_length)
    M_client_hex = M_client_data.decode()
    M_client = bytes.fromhex(M_client_hex)
    print_and_flush(f"Received M_client from Client: {M_client_hex}")

    # Server processes client's public value and computes session key
    server_session.process(A_hex, salt=user_data['salt'])
    print_and_flush("Server session processed.")

    # Verify client's proof
    print_and_flush("Verifying client's proof...")
    if server_session.verify_proof(M_client):
        M_server = server_session.key_proof_hash
        print_and_flush("Client's proof is valid.")
    else:
        raise Exception("Client's proof is invalid")

    # Step 4: Send M_server to client
    M_server_hex = M_server.hex()
    M_server_data = M_server_hex.encode()
    conn.sendall(len(M_server_data).to_bytes(4, 'big'))
    conn.sendall(M_server_data)
    print_and_flush("Sent M_server to Client")

    # Shared session key
    K = server_session.key
    print_and_flush(f"Authentication successful. Shared session key: {K.hex()}")

except Exception as e:
    print_and_flush(f"An error occurred: {e}")

finally:
    conn.close()
    sock.close()
    print_and_flush("Socket closed.")