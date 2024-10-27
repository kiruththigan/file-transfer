from Crypto.PublicKey import RSA

# Generate RSA key pair
key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()

# Save the keys to files
with open("private_key.pem", "wb") as f:
    f.write(private_key)

with open("public_key.pem", "wb") as f:
    f.write(public_key)


print("RSA key pair generated and saved successfully!")
