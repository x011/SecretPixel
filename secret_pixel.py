import argparse
import sys
import os
import random
from PIL import Image
import numpy as np
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import zlib
from getpass import getpass

"""
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

def encrypt_data(data, public_key):
    # Generate a random session key
    session_key = os.urandom(32)  # 32 bytes for 256-bit key
    
    # Derive a symmetric key from the session key
    salt = os.urandom(16)  # 16 bytes for 128-bit salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200000,  # Increased iterations for added security
        backend=default_backend()
    )
    key = kdf.derive(session_key)
    
    # Encrypt the data with AES
    iv = os.urandom(16)  # 16 bytes for 128-bit IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    # Encrypt the session key with RSA
    encrypted_session_key = public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return encrypted_session_key, salt, iv, encrypted_data

def decrypt_data(encrypted_session_key, salt, iv, encrypted_data, private_key):
    # Decrypt the session key with RSA
    session_key = private_key.decrypt(
        encrypted_session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Derive the symmetric key from the session key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200000,  # Increased iterations for added security
        backend=default_backend()
    )
    key = kdf.derive(session_key)
    
    # Decrypt the data with AES
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    
    return decrypted_data

def compute_seed_from_image_dimensions(image_path):
    with Image.open(image_path) as img:
        width, height = img.size
    return width + height

def hide_file_in_png(image_path, file_to_hide, output_image_path, public_key_path):
    # Load the public key
    with open(public_key_path, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    # Use the sum of the image dimensions as the seed
    seed = compute_seed_from_image_dimensions(image_path)
    prng = random.Random(seed)  # Create a new instance of a random number generator

    # Read the original image
    img = Image.open(image_path)


    # Check if the image is in a mode that can be converted to RGB or RGBA
    if img.mode not in ['RGB', 'RGBA', 'P', 'L']:
        raise ValueError("Image mode must be RGB, RGBA, P (palette-based), or L (grayscale).")

    # Convert to RGB if it's P or L mode (palette-based or grayscale)
    if img.mode == 'P' or img.mode == 'L':
        img = img.convert('RGB')

    # Convert to RGBA if not already in that format
    if img.mode != 'RGBA':
        img = img.convert('RGBA')

    # This will give you the original format of the image
    host_format = img.format  
    
    # If the format is None, try to determine it from the file extension
    if host_format is None:
        file_extension = os.path.splitext(image_path)[1].lower()
        extension_to_format = {
            '.tga': 'TGA',
            '.png': 'PNG',
            '.bmp': 'BMP',
            '.tif': 'TIFF',
            '.tiff': 'TIFF',
        }
        host_format = extension_to_format.get(file_extension)

    supported_formats = {'TGA', 'TIFF', 'BMP', 'PNG'}
    if host_format not in supported_formats:
        raise ValueError(f"Unsupported image format: {host_format}")
        
    pixels = np.array(img)
    
    # Read the file to hide
    with open(file_to_hide, 'rb') as f:
        file_bytes = f.read()
    
    # Compress the file
    compressed_data = zlib.compress(file_bytes)

    # Encrypt the compressed data
    encrypted_session_key, salt, iv, encrypted_data = encrypt_data(compressed_data, public_key)
    
    # Get the filename to store
    filename = os.path.basename(file_to_hide).encode()
    filename_size = len(filename)

    # Concatenate the encrypted session key, salt, iv, and encrypted data
    data_to_encode = (filename_size.to_bytes(4, 'big') + filename +
                      encrypted_session_key + salt + iv + encrypted_data)
    
    # Calculate the number of pixels needed
    file_size = len(data_to_encode)
    num_pixels_required = file_size * 8  # 8 bits per byte
    if num_pixels_required > pixels.size // 4:  # Divide by 4 for RGBA channels
        raise ValueError("Image is not large enough to hide the file.")

    # Generate a list of unique indices to hide the data
    pixel_indices = list(range(pixels.size // 4))
    prng.shuffle(pixel_indices)  # Shuffle using the seeded PRNG

    # Embed the file size in the first 64 pixels (8 bytes for file size)
    for i in range(64):
        idx = pixel_indices[i]
        bit = (file_size >> (63 - i)) & 0x1
        if (pixels[idx // pixels.shape[1], idx % pixels.shape[1], 0] & 0x1) != bit:
            pixels[idx // pixels.shape[1], idx % pixels.shape[1], 0] ^= 0x1

    # Embed each bit of the data to encode in the image using LSB matching
    for i, byte in enumerate(data_to_encode):
        for bit in range(8):
            idx = pixel_indices[64 + i * 8 + bit]
            if (pixels[idx // pixels.shape[1], idx % pixels.shape[1], 0] & 0x1) != ((byte >> (7 - bit)) & 0x1):
                pixels[idx // pixels.shape[1], idx % pixels.shape[1], 0] ^= 0x1
    


    # Check if the file already exists and prompt the user
    if os.path.exists(output_image_path):
        overwrite = input(f"The file '{output_image_path}' already exists. Overwrite? (y/n): ").lower()
        if overwrite != 'y':
            print("Extraction cancelled.")
            return
    
    # Save the new image
    new_img = Image.fromarray(pixels, 'RGBA')

    if host_format == 'PNG':
        new_img.save(output_image_path, format='PNG', optimize=True)
    elif host_format == 'BMP':
        new_img.save(output_image_path, format='BMP', optimize=True)
    elif host_format == 'TGA':
        new_img.save(output_image_path, format='TGA', optimize=True)
    elif host_format == 'TIFF':
        new_img.save(output_image_path, format='TIFF', optimize=True)
    else:
        # If the format is not one of the supported/expected formats, raise an error.
        raise ValueError(f"Unsupported image format: {host_format}")

    print(f"File '{file_to_hide}' has been successfully hidden in '{output_image_path}'.")





def extract_file_from_png(image_path, output_file_path, private_key_path):
    # Load the private key
    passphrase = getpass("Enter the private key passphrase: ")
    with open(private_key_path, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=passphrase.encode(),
            backend=default_backend()
        )
    
    # Determine the size of the encrypted session key based on the private key size
    encrypted_session_key_size = private_key.key_size // 8
    
    # Use the sum of the image dimensions as the seed
    seed = compute_seed_from_image_dimensions(image_path)
    prng = random.Random(seed)  # Create a new instance of a random number generator


    # Read the steganographed image
    img = Image.open(image_path)
    if img.mode not in ['RGB', 'RGBA']:
        raise ValueError("Image must be in RGB or RGBA format.")
    
    # Convert to RGBA if not already in that format
    if img.mode != 'RGBA':
        img = img.convert('RGBA')
    
    pixels = np.array(img)
    
    # Flatten the image array for easier processing
    flat_pixels = pixels.flatten()
    
    # Use only the red channel for RGBA
    channel_multiplier = 4

    # Extract the file size from the first 64 pixels
    file_size = 0
    for i in range(64):
        file_size = (file_size << 1) | (flat_pixels[i * channel_multiplier] & 0x1)
    
    # Calculate the number of bytes that can be extracted
    num_bytes_to_extract = file_size
    
    # Prepare a list to store the extracted bytes
    extracted_bytes = []
    

    # Generate a list of unique indices to extract the data
    pixel_indices = list(range(pixels.size // 4))
    prng.shuffle(pixel_indices)  # Shuffle using the seeded PRNG

    # Extract the file size from the first 64 pixels
    file_size = 0
    for i in range(64):
        idx = pixel_indices[i]
        file_size = (file_size << 1) | (pixels[idx // pixels.shape[1], idx % pixels.shape[1], 0] & 0x1)

    # Calculate the number of bytes that can be extracted
    num_bytes_to_extract = file_size

    # Extract the hidden bits and reconstruct the bytes using the same indices
    extracted_bytes = []
    for i in range(num_bytes_to_extract):
        byte = 0
        for bit in range(8):
            idx = pixel_indices[64 + i * 8 + bit]
            byte = (byte << 1) | (pixels[idx // pixels.shape[1], idx % pixels.shape[1], 0] & 0x1)
        extracted_bytes.append(byte)
    
    # Convert the extracted bytes to a byte array
    data_to_decode = bytes(extracted_bytes)

    # Extract the filename size and filename
    filename_size = int.from_bytes(data_to_decode[:4], 'big')
    filename = data_to_decode[4:4 + filename_size].decode()
    
    # Extract the session key, salt, iv, and encrypted data
    offset = 4 + filename_size
    encrypted_session_key = data_to_decode[offset:offset + encrypted_session_key_size]
    salt = data_to_decode[offset + encrypted_session_key_size:offset + encrypted_session_key_size + 16]
    iv = data_to_decode[offset + encrypted_session_key_size + 16:offset + encrypted_session_key_size + 32]
    encrypted_data = data_to_decode[offset + encrypted_session_key_size + 32:]
    
    # Decrypt the data
    decrypted_data = decrypt_data(encrypted_session_key, salt, iv, encrypted_data, private_key)
    
    # Decompress the decrypted data
    decompressed_data = zlib.decompress(decrypted_data)
    
    # If no output file path is provided, use the extracted filename
    if not output_file_path:
        output_file_path = os.path.join(os.getcwd(), filename)

    # Check if the file already exists and prompt the user
    if os.path.exists(output_file_path):
        overwrite = input(f"The file '{output_file_path}' already exists. Overwrite? (y/n): ").lower()
        if overwrite != 'y':
            print("Extraction cancelled.")
            return
        
    # Write the decompressed data to the output file
    with open(output_file_path, 'wb') as f:
        f.write(decompressed_data)

    print(f"File extracted to {output_file_path}")


def main():
    parser = argparse.ArgumentParser(description='SecretPixel - Advanced Steganography Tool', epilog="Example commands:\n"
                                            "  Hide: python secret_pixel.py hide host.png secret.txt mypublickey.pem output.png\n"
                                            "  Extract: python secret_pixel.py extract carrier.png myprivatekey.pem [extracted.txt]",
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    subparsers = parser.add_subparsers(dest='command')

    # Subparser for hiding a file
    hide_parser = subparsers.add_parser('hide', help='Hide a file inside an image', epilog="Example: python secret_pixel.py hide host.png secret.txt mypublickey.pem output.png", formatter_class=argparse.RawDescriptionHelpFormatter)
    hide_parser.add_argument('host', type=str, help='Path to the host image')
    hide_parser.add_argument('secret', type=str, help='Path to the secret file to hide')
    hide_parser.add_argument('pubkey', type=str, help='Path to the public key for encryption')
    hide_parser.add_argument('output', type=str, help='Path to the output image with embedded data')


    # Subparser for extracting a file
    extract_parser = subparsers.add_parser('extract', help='Extract a file from an image', epilog="Example: python secret_pixel.py extract carrier.png  myprivatekey.pem [extracted.txt]",
                                           formatter_class=argparse.RawDescriptionHelpFormatter)
    extract_parser.add_argument('carrier', type=str, help='Path to the image with embedded data')
    extract_parser.add_argument('privkey', type=str, help='Path to the private key for decryption')

    extract_parser.add_argument('extracted', nargs='?', type=str, default=None, help='Path to save the extracted secret file (optional, defaults to the original filename)')



    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    if args.command == 'hide':
        hide_file_in_png(args.host, args.secret, args.output, args.pubkey)
    elif args.command == 'extract':
        # If no output file path is provided, use None to trigger default behavior
        output_file_path = args.extracted if args.extracted else None
        extract_file_from_png(args.carrier, output_file_path, args.privkey)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
