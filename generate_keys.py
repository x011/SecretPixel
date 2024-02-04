from Crypto.PublicKey import RSA
from getpass import getpass

mykey = RSA.generate(4096)

pwd = getpass("RSA Private Key Passphrase:").encode('utf-8')

with open("myprivatekey.pem", "wb") as f:

	data = mykey.export_key(passphrase=pwd,
	pkcs=8,
	protection='PBKDF2WithHMAC-SHA512AndAES256-CBC',
	prot_params={'iteration_count':131072})

	f.write(data)


with open("mypublickey.pem", "wb") as f:

    data = mykey.public_key().export_key()
    f.write(data)