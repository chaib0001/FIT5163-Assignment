import socket
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh
from cryptography.hazmat.primitives import serialization, hashes
import pickle

def recv_all(sock, n):
    """Helper function to receive exactly n bytes from a socket."""
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

# Step 1: Generate RSA private/public key pair for signing
private_key_server = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key_server = private_key_server.public_key()

# Serialize the RSA public key
rsa_public_bytes_server = public_key_server.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Step 5: Set up the server to receive client's data
server_address = ('0.0.0.0', 65443)  # Bind to all interfaces
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(server_address)
sock.listen(1)
print("Waiting for Client to connect...")

connection, client_address = sock.accept()
print(f"Connected to Client from {client_address}")

try:
    # Receive data length from client
    data_length_bytes = recv_all(connection, 4)
    if data_length_bytes is None:
        raise Exception("Failed to receive data length from Client")
    data_length = int.from_bytes(data_length_bytes, 'big')

    # Receive client's data
    received_data = recv_all(connection, data_length)
    if received_data is None:
        raise Exception("Failed to receive data from client")

    data_from_client = pickle.loads(received_data)
    print("Received data from client")

    # Extract data
    dh_parameter_bytes = data_from_client['dh_parameters']
    rsa_public_bytes_client = data_from_client['rsa_public_key']
    dh_public_bytes_client = data_from_client['dh_public_key']
    signature_client = data_from_client['signature']

    # Load client's RSA public key
    public_key_client = serialization.load_pem_public_key(rsa_public_bytes_client)

    # Verify client's signature on the DH parameters and public key
    public_key_client.verify(
        signature_client,
        dh_parameter_bytes + dh_public_bytes_client,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    print("Client's signature is valid")

    # Load DH parameters from client
    parameters_server = serialization.load_pem_parameters(dh_parameter_bytes)

    # Generate server's DH private and public keys using the received parameters
    dh_private_key_server = parameters_server.generate_private_key()
    dh_public_key_server = dh_private_key_server.public_key()

    # Serialize the DH public key
    dh_public_bytes_server = dh_public_key_server.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Sign the serialized DH public key using RSA private key
    signature_server = private_key_server.sign(
        dh_public_bytes_server,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

    # Compute shared secret
    dh_public_key_client = serialization.load_pem_public_key(dh_public_bytes_client)
    shared_secret_server = dh_private_key_server.exchange(dh_public_key_client)
    print(f"Server's Shared Secret: {shared_secret_server.hex()}")

    # Prepare data to send back to client
    data_to_send = {
        'rsa_public_key': rsa_public_bytes_server,
        'dh_public_key': dh_public_bytes_server,
        'signature': signature_server
    }

    # Serialize data and send length prefix
    serialized_data = pickle.dumps(data_to_send)
    data_length = len(serialized_data)
    connection.sendall(data_length.to_bytes(4, 'big'))
    connection.sendall(serialized_data)
    print("Server's data sent to Client")

except Exception as e:
    print(f"An error occurred: {e}")

finally:
    connection.close()
