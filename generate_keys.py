from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from getpass import getpass

# Generate the private key with a key size of 4096
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096,
    backend=default_backend()
)

# Prompt the user for a passphrase to encrypt the private key
password = getpass("RSA Private Key Passphrase: ").encode('utf-8')

# Define the encryption algorithm with the desired characteristics
encryption_algorithm = serialization.BestAvailableEncryption(password)

# Serialize the private key with the specified encryption algorithm
pem_private = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=encryption_algorithm
)

# Write the encrypted private key to a file
with open("myprivatekey.pem", "wb") as f:
    f.write(pem_private)

# Generate the public key
public_key = private_key.public_key()

# Serialize the public key
pem_public = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Write the public key to a file
with open("mypublickey.pem", "wb") as f:
    f.write(pem_public)


print("myprivatekey.pem has been created successfully.")
print("mypublickey.pem has been created successfully.")