# Run the following commands in order

### 1: Create python virtual environment

```bash
python -m venv .venv
```

```bash
.\.venv\Scripts\activate
```

### 2: Install required packages

```bash
pip install -r requirements.txt
```

### 3: Run the python files in following order

```bash
python rsa_key_generation.py
```

```bash
python receiver.py
```

```bash
python sender.py
```

# Guide & Explanation

    Use AES for symmetric encryption – Encrypt the file's content before sending.
    Use RSA for asymmetric encryption – Encrypt the AES key and nonce, ensuring secure key exchange.
    Use SHA-256 hashing – Compute a hash of the file for integrity verification.

    Explanation
    AES Encryption:

    The file content is encrypted using AES before sending.
    RSA Encryption for Key Exchange:

    The AES key and nonce are encrypted with RSA (public key) and sent to the receiver.
    The receiver decrypts them using the RSA private key.
    SHA-256 Hash for Integrity Check:

    The hash of the original file is computed and sent along with the data.
    The receiver verifies the file by comparing the received hash with the computed hash of the decrypted content.
    End Marker (<END>):

    Marks the end of the transmission to handle stream reading properly.

    This approach ensures:

    Confidentiality: AES encrypts the content.
    Secure Key Exchange: RSA encrypts the AES key and nonce.
    Integrity: SHA-256 ensures that the file has not been altered during transmission.
