# receiver.py
import socket
import tqdm
from Crypto.Cipher import AES
from hashlib import sha256
from datetime import datetime
import os

# Hardcoded AES key and nonce (same as sender)
key = b"TheNeuralNineKey"
nonce = b"TheNeuralNineNce"


def get_unique_filename(filename):
    if not os.path.exists(filename):
        return filename
    base, ext = os.path.splitext(filename)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{base}_{timestamp}{ext}"


print("[*] Setting up the server...")
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("localhost", 8080))
server.listen()
print("[+] Server is listening on port 8080...")

client, addr = server.accept()
print(f"[+] Connection established with {addr}")

try:  # try exception to error handle
    print("[*] Receiving metadata...")
    buffer = b""
    while b"<META_END>" not in buffer:
        buffer += client.recv(1024)

    metadata, remaining = buffer.split(b"<META_END>", 1)
    file_name, file_size, received_hash = metadata.decode().split("\n")[:3]
    file_size = int(file_size)

    print(f"[+] Received Filename: {file_name}")
    print(f"[+] Expected File Size: {file_size} bytes")
    print(f"[+] Received File Hash: {received_hash}")

    unique_file_name = get_unique_filename(file_name)
    print(f"[+] Saving file as: {unique_file_name}")

    print("[*] Receiving encrypted file content...")
    file = open(unique_file_name, "wb")
    file_bytes = remaining  # Any leftover data from the buffer
    progress = tqdm.tqdm(unit="B", unit_scale=True, unit_divisor=1024, total=file_size)

    while len(file_bytes) < file_size:
        data = client.recv(1024)
        if not data:  # Connection closed
            print("[!] Connection closed unexpectedly.")
            break
        if data.endswith(b"<END>"):
            file_bytes += data[:-5]
            break
        file_bytes += data
        progress.update(len(data))

    # Remove the <END> marker
    file_bytes = file_bytes[:-5]

    # Check the total size received
    if len(file_bytes) != file_size:
        print(
            f"[!] Received file size mismatch! Expected: {file_size}, Received: {len(file_bytes)}"
        )
        file.close()
        client.close()
        server.close()
        exit(1)

    print("[*] Decrypting the file content using AES...")
    cipher_aes = AES.new(key, AES.MODE_EAX, nonce=nonce)
    decrypted_data = cipher_aes.decrypt(file_bytes)

    file.write(decrypted_data)
    file.close()

    print("[+] File decrypted and saved successfully!")

    # Send acknowledgment back to sender
    client.send(b"ACK")  # Send acknowledgment
    print("[+] Acknowledgment sent to sender.")

    print("[*] Verifying file integrity...")
    computed_hash = sha256(decrypted_data).hexdigest()
    if computed_hash == received_hash:
        print("[+] File integrity verified successfully! Hashes match.")
    else:
        print("[!] Hash mismatch! The file may be corrupted.")
        print(f"Computed Hash: {computed_hash}, Expected Hash: {received_hash}")

except Exception as e:  # catch exception
    print(f"Error in receiving file: {str(e)}")
finally:  # closing connection
    client.close()
    server.close()
    print("[+] Connection closed.")
