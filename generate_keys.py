from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from getpass import getpass

def generate_keys():
    password = getpass("RSA Private Key Passphrase:").encode('utf-8')
    
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )
    
    # Serialize private key with passphrase
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password)
    )
    
    # Write private key to file
    with open("myprivatekey.pem", "wb") as f:
        f.write(pem_private)
    
    # Generate public key
    public_key = private_key.public_key()
    
    # Serialize public key
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Write public key to file
    with open("mypublickey.pem", "wb") as f:
        f.write(pem_public)

generate_keys()