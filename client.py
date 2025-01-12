import socket
import ssl
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64
import os
import threading

# Encryption and HMAC settings
PASSWORD = b"namnake@SSY"
SALT = b"encryption_salt"
HMAC_KEY_SALT = b"hmac_key_salt"
BLOCK_SIZE = 128

# The expected certificate hash (SHA-256 fingerprint you generated)
EXPECTED_CERT_HASH = "74:E7:3F:62:BC:88:C3:BB:94:68:F6:1F:3A:D8:25:7B:AD:75:20:74:29:C2:12:5C:30:06:02:56:93:9D:C1:AB"

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password)

KEY = derive_key(PASSWORD, SALT)
HMAC_KEY = derive_key(PASSWORD, HMAC_KEY_SALT)

def encrypt(data):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(BLOCK_SIZE).padder()
    padded_data = padder.update(data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + encrypted_data)

def decrypt(encrypted_data):
    encrypted_data = base64.b64decode(encrypted_data)
    iv = encrypted_data[:16]
    encrypted_data = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()
    return unpadder.update(decrypted_padded_data) + unpadder.finalize()

def compute_hmac(data):
    return hmac.new(HMAC_KEY, data, hashlib.sha256).hexdigest()

def verify_hmac(data, received_hmac):
    computed_hmac = compute_hmac(data)
    return hmac.compare_digest(computed_hmac, received_hmac)

def verify_certificate(cert):
    # Get the SHA-256 fingerprint of the server certificate
    cert_der = ssl.DER_cert_to_PEM_cert(cert)  # Convert the cert to PEM format
    cert_hash = hashlib.sha256(cert_der.encode()).hexdigest().upper()  # Calculate the SHA-256 hash of the certificate

    # Compare the computed hash with the expected one
    if cert_hash != EXPECTED_CERT_HASH:
        raise ssl.SSLError(f"Certificate fingerprint mismatch! Expected {EXPECTED_CERT_HASH}, but got {cert_hash}")
    else:
        print("Certificate fingerprint matches.")

def send_message(server_socket):
    while True:
        try:
            message = input("Enter message to send (or type SEND_FILE to send a file): ").strip()
            if message.lower() == "send_file":
                send_file(server_socket)
            else:
                encrypted_message = encrypt(message.encode('utf-8'))
                hmac_value = compute_hmac(encrypted_message)
                server_socket.send(encrypted_message + b"::" + hmac_value.encode('utf-8'))
        except Exception as e:
            print(f"Error sending message: {e}")
            break

def send_file(server_socket):
    file_path = input("Enter the file path to send: ").strip()
    if not os.path.exists(file_path):
        print("File does not exist!")
        return

    file_name = os.path.basename(file_path)
    file_size = os.path.getsize(file_path)
    header = f"FILE:{file_name}:{file_size}"
    encrypted_header = encrypt(header.encode('utf-8'))
    header_hmac = compute_hmac(encrypted_header)
    server_socket.send(encrypted_header + b"::" + header_hmac.encode('utf-8'))

    with open(file_path, "rb") as file:
        while chunk := file.read(1024):
            encrypted_chunk = encrypt(chunk)
            chunk_hmac = compute_hmac(encrypted_chunk)
            server_socket.send(len(encrypted_chunk).to_bytes(4, 'big') + encrypted_chunk + chunk_hmac.encode('utf-8'))
    print(f"File '{file_name}' sent successfully.")

def receive_file(server_socket, header):
    _, file_name, file_size = header.split(":")
    file_size = int(file_size)

    with open(file_name, "wb") as file:
        bytes_received = 0
        while bytes_received < file_size:
            chunk_size = int.from_bytes(server_socket.recv(4), 'big')
            encrypted_chunk = server_socket.recv(chunk_size)
            chunk_hmac = server_socket.recv(64).decode('utf-8')

            if not verify_hmac(encrypted_chunk, chunk_hmac):
                print("HMAC verification failed for file chunk. Aborting.")
                return

            chunk = decrypt(encrypted_chunk)
            file.write(chunk)
            bytes_received += len(chunk)

    print(f"File '{file_name}' received successfully.")

def handle_server(server_socket):
    def receive_data():
        while True:
            try:
                encrypted_message = server_socket.recv(1024)
                if not encrypted_message:
                    print("\nServer disconnected.")
                    break

                message, received_hmac = encrypted_message.rsplit(b"::", 1)
                if not verify_hmac(message, received_hmac.decode('utf-8')):
                    print("\nHMAC verification failed for message. Aborting.")
                    break

                decrypted_message = decrypt(message).decode('utf-8')
                if decrypted_message.startswith("FILE:"):
                    receive_file(server_socket, decrypted_message)
                else:
                    print(f"\nServer: {decrypted_message}")
            except Exception as e:
                print(f"Error receiving message: {e}")
                break

    threading.Thread(target=receive_data, daemon=True).start()
    send_message(server_socket)

def start_client():
    host = '10.20.14.153'  # Replace with the server's IP address
    port = 12345

    context = ssl.create_default_context()
    context.load_verify_locations(cafile="server.crt")  # Load server certificate for validation

    # Create a secure connection to the server
    connection = socket.create_connection((host, port))
    server_socket = context.wrap_socket(connection, server_hostname=host)
    print("Secure connection established with the server.")

    # Get the server certificate and verify its fingerprint
    server_cert = server_socket.getpeercert(True)  # Retrieve the server certificate
    verify_certificate(server_cert)  # Verify the fingerprint

    # Now handle communication (sending/receiving data)...
    handle_server(server_socket)

if __name__== "__main__":
    start_client()