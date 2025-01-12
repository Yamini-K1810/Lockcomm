# Lockcomm
This project implements a secure communication and file transfer system using Python. It leverages cryptographic primitives for encryption, authentication, and secure communication over a TLS-encrypted channel. The implementation consists of a server (`server.py`) and a client (`client.py`), designed for sending and receiving both text messages and files securely.

## Features
- **End-to-End Encryption:** AES encryption (with CBC mode) is used to secure message and file content.
- **HMAC for Integrity:** HMAC (SHA-256) ensures the integrity of all messages and file chunks.
- **TLS Security:** The communication channel is secured with SSL/TLS.
- **File Transfer:** Ability to send and receive files securely.
- **Message Authentication:** Verifies data authenticity with HMAC signatures.
- **Certificate Validation:** Ensures the server's certificate matches an expected SHA-256 fingerprint.

## Prerequisites
- Python 3.7 or later.
- `cryptography` library installed (`pip install cryptography`).

## Installation
1. Clone this repository or copy the files.
2. Install the required dependencies:
   ```bash
   pip install cryptography
   ```
3. Generate server certificates:
   ```bash
   openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes
   ```
4. Copy the `server.crt` file to the client machine.

## Configuration
### Server (`server.py`):
- Host: `0.0.0.0` (listens on all interfaces).
- Port: `12345`.
- TLS Certificate: `server.crt` and `server.key`.

### Client (`client.py`):
- Server IP: Update the `host` variable with the server's IP address.
- Port: `12345`.
- Server Certificate: The `server.crt` file is used to validate the server's identity.

## How to Run
### Server
1. Start the server:
   ```bash
   python server.py
   ```
2. The server will listen for incoming client connections.

### Client
1. Start the client:
   ```bash
   python client.py
   ```
2. The client will establish a secure connection to the server.

## Usage
### Sending Messages
- After establishing a connection, type a message in the client or server console to send it to the other party.
- Messages are encrypted using AES and validated using HMAC.

### Sending Files
1. Type `SEND_FILE` in the console.
2. Enter the file path of the file to send.
3. The file is encrypted, split into chunks, and transferred securely.

### Receiving Files
- Received files are decrypted and saved with their original filename in the current working directory.

## Security Features
1. **AES Encryption:** All messages and files are encrypted using AES with a 256-bit key in CBC mode.
2. **HMAC Verification:** HMAC-SHA256 ensures the integrity of all messages and files.
3. **TLS Encryption:** The communication channel is secured with SSL/TLS for transport-level encryption.
4. **Certificate Validation:** The client verifies the server's certificate fingerprint to prevent man-in-the-middle (MITM) attacks.

## Known Limitations
- Hardcoded SALT and PASSWORD values: For production, these should be managed securely and not hardcoded.
- Single-threaded file transfer: While the server can handle multiple clients simultaneously, file transfers are blocking per client.

## Example Communication
1. **Message Exchange:**
   - Server: "Hello, Client!"
   - Client: "Hi, Server!"
2. **File Transfer:**
   - Client: Sends `example.txt` to the server.
   - Server: Receives and saves `example.txt`.

## Troubleshooting
- **Certificate Errors:** Ensure `server.crt` is correctly shared with the client and matches the server's certificate.
- **Connection Errors:** Verify the server's IP address and port.
- **HMAC Verification Failed:** Ensure both the client and server use the same `PASSWORD` and `SALT`.

## License
This project is open-source and available under the MIT License.
