import socket
from srptools import SRPContext, SRPClientSession
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

# Client configuration
SERVER_HOST = '192.168.66.148'  # Replace with server's IP address
SERVER_PORT = 65443
USERNAME = 'user'
PASSWORD = 'secure_password'

print_and_flush("Starting SRP Client script.")

# Start client
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    sock.connect((SERVER_HOST, SERVER_PORT))
    print_and_flush("Connected to Server")
except Exception as e:
    print_and_flush(f"Error connecting to Server: {e}")
    exit(1)

try:
    print_and_flush("Initializing SRPContext...")
    ctx = SRPContext(USERNAME, PASSWORD)
    print_and_flush("SRPContext initialized.")

    print_and_flush("Initializing SRPClientSession...")
    client_session = SRPClientSession(ctx)
    print_and_flush("SRPClientSession initialized.")

    print_and_flush("Computing A (client public value)...")
    A_hex = client_session.public  # Already a hex string
    print_and_flush(f"A computed: {A_hex}")

    client_data = {
        'username': USERNAME,
        'A': A_hex,
    }
    print_and_flush(f"Client data prepared: {client_data}")

    # Send client data
    data = pickle.dumps(client_data)
    data_length = len(data)
    sock.sendall(data_length.to_bytes(4, 'big'))
    sock.sendall(data)
    print_and_flush("Sent username and A to Server")

    # Step 2: Receive salt and B from server
    data_length_bytes = recv_all(sock, 4)
    data_length = int.from_bytes(data_length_bytes, 'big')
    data = recv_all(sock, data_length)
    server_data = pickle.loads(data)

    # Extract salt and B as hex strings
    SALT_hex = server_data['salt']
    B_hex = server_data['B']

    print_and_flush(f"Received salt and B from Server:\nsalt={SALT_hex}\nB={B_hex}")

    # Update client session with received salt and server public value
    print_and_flush("Processing Server's public value and salt...")
    client_session.process(B_hex, salt=SALT_hex)
    print_and_flush("Client session processed.")

    # Step 3: Compute M_client (client's proof)
    M_client = client_session.key_proof
    print_and_flush(f"Computed M_client (client's proof): {M_client.hex()}")

    # Send M_client to server
    M_client_hex = M_client.hex()
    M_client_data = M_client_hex.encode()
    sock.sendall(len(M_client_data).to_bytes(4, 'big'))
    sock.sendall(M_client_data)
    print_and_flush("Sent M_client to Server")

    # Step 4: Receive M_server and verify
    data_length_bytes = recv_all(sock, 4)
    data_length = int.from_bytes(data_length_bytes, 'big')
    M_server_data = recv_all(sock, data_length)
    M_server_hex = M_server_data.decode()
    M_server = bytes.fromhex(M_server_hex)
    print_and_flush(f"Received M_server from Server: {M_server_hex}")

    # Verify server's proof
    print_and_flush("Verifying Server's proof...")
    if client_session.verify_proof(M_server):
        K = client_session.key
        print_and_flush(f"Authentication successful. Shared session key: {K.hex()}")
    else:
        print_and_flush("Authentication failed. Server's proof is invalid.")

except Exception as e:
    print_and_flush(f"An error occurred: {e}")

finally:
    sock.close()
    print_and_flush("Socket closed.")