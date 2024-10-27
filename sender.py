# sender.py
import os
import socket
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from hashlib import sha256

# Configuration
key = b"TheNeuralNineKey"
nonce = b"TheNeuralNineNce"
file_path = "file.txt"

print("[*] Reading the file...")
with open(file_path, "rb") as f:
    data = f.read()

print("[*] Encrypting the file using AES...")
cipher_aes = AES.new(key, AES.MODE_EAX, nonce=nonce)
encrypted_data = cipher_aes.encrypt(data)
print(f"encrypted_data: {encrypted_data}")

print("[*] Generating SHA-256 hash...")
file_hash = sha256(data).hexdigest()
print(f"[+] File Hash: {file_hash}")

print("[*] Loading RSA public key...")
with open("public_key.pem", "rb") as f:
    public_key = RSA.import_key(f.read())

cipher_rsa = PKCS1_OAEP.new(public_key)

print("[*] Encrypting AES key and nonce using RSA...")
encrypted_key = cipher_rsa.encrypt(key)
encrypted_nonce = cipher_rsa.encrypt(nonce)

print("[*] Connecting to the server...")
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("localhost", 8080))

print("[*] Sending metadata and encrypted content...")
metadata = (
    f"{os.path.basename(file_path)}\n{len(encrypted_data)}\n{file_hash}\n<META_END>"
)
client.send(metadata.encode())  # Send metadata with a marker

print("[*] Sending encrypted content...")
# client.sendall(encrypted_key)
# client.send(b"<ENC_KEY_END>")
# client.sendall(encrypted_nonce)
# client.send(b"<ENC_NONCE_END>")
client.sendall(encrypted_data)
client.send(b"<END>")

# Wait for acknowledgment
ack = client.recv(1024)  # Wait for acknowledgment from the receiver
if ack == b"ACK":
    print("[+] Acknowledgment received from receiver.")
else:
    print("[!] No acknowledgment received.")

print("[+] File and metadata sent successfully!")
client.close()
