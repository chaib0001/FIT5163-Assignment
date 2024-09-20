import socket
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh
from cryptography.hazmat.primitives import serialization, hashes
import pickle

def recv_all(sock, n):
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

# Step 1: Generate RSA private/public key pair for signing
private_key_client = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key_client = private_key_client.public_key()

# Step 2: Generate Diffie-Hellman parameters and private key
parameters = dh.generate_parameters(generator=2, key_size=2048)
dh_private_key_client = parameters.generate_private_key()
dh_public_key_client = dh_private_key_client.public_key()

# Serialize the DH parameters to send to server
dh_parameter_bytes = parameters.parameter_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.ParameterFormat.PKCS3
)

# Step 3: Serialize the DH public key
dh_public_bytes_client = dh_public_key_client.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Serialize the RSA public key
rsa_public_bytes_client = public_key_client.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Step 4: Sign the serialized DH public key and parameters using RSA private key
signature_client = private_key_client.sign(
    dh_parameter_bytes + dh_public_bytes_client,
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
    hashes.SHA256()
)

# Step 5: Send serialized DH parameters, DH public key, RSA public key, and signature to server
server_address = ('192.168.66.148', 65443)  # server's IP address
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    sock.connect(server_address)
    print("Connected to Server")

    # Prepare data to send
    data_to_send = {
        'dh_parameters': dh_parameter_bytes,
        'rsa_public_key': rsa_public_bytes_client,
        'dh_public_key': dh_public_bytes_client,
        'signature': signature_client
    }

    # Serialize data and send length prefix
    serialized_data = pickle.dumps(data_to_send)
    data_length = len(serialized_data)
    sock.sendall(data_length.to_bytes(4, 'big'))
    sock.sendall(serialized_data)
    print("Client's data sent to Server")

    # Receive data length from server
    data_length_bytes = recv_all(sock, 4)
    if data_length_bytes is None:
        raise Exception("Failed to receive data length from Server")
    data_length = int.from_bytes(data_length_bytes, 'big')

    # Receive server's data
    received_data = recv_all(sock, data_length)
    if received_data is None:
        raise Exception("Failed to receive data from Server")

    data_from_server = pickle.loads(received_data)
    print("Received data from Server")

    # Extract data
    rsa_public_bytes_server = data_from_server['rsa_public_key']
    dh_public_bytes_server = data_from_server['dh_public_key']
    signature_server = data_from_server['signature']

    # Load server's RSA public key
    public_key_server = serialization.load_pem_public_key(rsa_public_bytes_server)

    # Verify server's signature
    public_key_server.verify(
        signature_server,
        dh_public_bytes_server,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    print("Server's signature is valid")

    # Load server's DH public key
    dh_public_key_server = serialization.load_pem_public_key(dh_public_bytes_server)

    # Compute shared secret
    shared_secret_client = dh_private_key_client.exchange(dh_public_key_server)
    print(f"Client's Shared Secret: {shared_secret_client.hex()}")

except Exception as e:
    print(f"An error occurred: {e}")
finally:
    sock.close()