# SecretPixel - Advanced Image Steganography Tool

SecretPixel is a cutting-edge steganography tool designed to securely conceal sensitive information within images. It stands out in the realm of digital steganography by combining advanced encryption, compression, and a seeded Least Significant Bit (LSB) technique to provide a robust solution for embedding data undetectably.

## Key Features

- **Advanced Encryption**: SecretPixel uses AES-256 encryption for the data, with a session key that is further encrypted using RSA public key cryptography. This two-tier encryption ensures that only the holder of the corresponding RSA private key can decrypt the hidden information, providing a high level of security.

- **Compression**: Before encryption, the data is compressed using zlib to reduce its size. This not only makes the process more efficient but also helps in minimizing patterns that could be detected by steganalysis tools.

- **Seeded LSB Steganography**: The tool employs a seeded random number generator to determine the pixel positions used for embedding the data. This approach scatters the hidden bits throughout the image, making it more resistant to detection by steganalysis tools like zsteg.

- **File Name Storage**: SecretPixel stores the original filename of the hidden data within the image. This allows for the file to be extracted with its original name, providing additional convenience and maintaining file identity.

- **Cross-Platform Compatibility**: Written in Python, SecretPixel is cross-platform and can be used on any system with Python installed.

## Installation

To use SecretPixel, clone the repository or download the source code from GitHub. Ensure you have Python 3 installed on your system, along with the required packages:

```
git clone https://github.com/x011/SecretPixel.git
cd SecretPixel
pip install -r requirements.txt
```


## Generating RSA Keys

SecretPixel uses RSA public key cryptography to secure the embedded data. To get started, you will need to generate a pair of RSA keys: a private key and a public key. We provide an auxiliary Python script to facilitate this process.

### Key Generation Script

The `generate_keys.py` script creates a 4096-bit RSA key pair. To generate your keys, follow these steps:

1. Run the script using Python:

   `python generate_keys.py`

2. When prompted, enter a passphrase for the RSA private key. This passphrase adds a layer of security by encrypting your private key with AES-256, ensuring that even if the key is compromised, it cannot be used without the passphrase. Choose a strong, complex passphrase for maximum protection.

3. Upon successful completion, the script will create two files in the current directory:
   - `myprivatekey.pem`: Your RSA private key, encrypted with the passphrase you provided.
   - `mypublickey.pem`: Your RSA public key, which can be safely shared with others.


## Usage

### Hiding a File

To hide a file within an image, use the following command:

`python secret_pixel.py hide host.png secret.txt mypublickey.pem output.png`

This command embeds `secret.txt` inside `host.png` using the public key `mypublickey.pem`, and saves the steganographed image as `output.png`.

### Extracting a File

To extract a hidden file from an image, use the following command:

`python secret_pixel.py extract carrier.png myprivatekey.pem [extracted.txt]`

This extracts the hidden file from `carrier.png` using the private key `myprivatekey.pem`. If `extracted.txt` is not provided, the file will be extracted with its original filename.


## Security and Stealth

SecretPixel is designed with security and stealth in mind. The encryption process ensures that the hidden data remains confidential, while the compression and random distribution of data make it extremely difficult for steganalysis tools to detect the presence of embedded information. The use of a seeded random number generator adds an additional layer of security, as the pattern of embedded data cannot be predicted without knowing the seed.


## Encryption:

- **AES Encryption**: SecretPixel uses AES (Advanced Encryption Standard) with a 256-bit key for symmetric encryption. The key is derived from a randomly generated 256-bit session key using PBKDF2 (Password-Based Key Derivation Function 2) with HMAC-SHA-256 as the hash function. The number of iterations for the key derivation is set to 200,000, which increases the cost of brute-force attacks.

- **RSA Encryption**: The session key is encrypted using RSA public key cryptography with OAEP (Optimal Asymmetric Encryption Padding) and SHA-256 for both the MGF1 (Mask Generation Function) and the hashing algorithm. A 4096-bit RSA key size is recommended to ensure a high level of security (default on generate_keys.py).

- **Initialization Vector (IV)**: A 128-bit IV is used for AES in CBC (Cipher Block Chaining) mode. The IV ensures that identical plaintext blocks will produce different ciphertext blocks, enhancing security.

- **Padding**: PKCS7 padding is used to ensure that the plaintext data is a multiple of the AES block size (128 bits). This padding is removed after decryption.


## Supported File Types

SecretPixel is designed to work with a variety of image file formats. The following formats are supported for the host image:

- **PNG (Portable Network Graphics)**: Ideal for steganography due to its lossless compression.
- **BMP (Bitmap Image File)**: A raw image format that provides a simple structure for easy data manipulation.
- **TGA (Targa Graphic)**: Commonly used in the video and animation industry, supporting various pixel formats.
- **TIFF (Tagged Image File Format)**: Widely used in the imaging and publishing industry, known for its flexibility and support for multiple image types.

It is important to note that the chosen host image format can impact the effectiveness of the steganography process. Lossless formats like PNG and TIFF are preferred to ensure that no data is lost during the embedding process.

## Host Image Requirements

When using SecretPixel, the host image serves as the carrier for the hidden data. To maintain the integrity of the steganography process and to avoid detection, it is crucial to consider the following:

- **Image Size**: The host image must be large enough to accommodate the hidden file. The size of the image determines the maximum amount of data that can be securely embedded. As a rule of thumb, the host image should have a capacity (in bytes) at least three times the size of the file to be hidden to ensure that the modifications are subtle and widely dispersed.

- **Image Content**: Images with a high level of detail and color variation are better suited for steganography. They provide more "noise" in which to hide the data, making it harder for steganalysis tools to detect anomalies.

- **Avoid Compression Artifacts**: If using a format that supports compression, such as TIFF, care should be taken to avoid compression artifacts that could interfere with the hidden data. It is recommended to use lossless compression settings.

- **Preparation**: Before embedding data, the host image should not contain any previous steganographic content or sensitive metadata that could conflict with the new data or reveal its presence.

By carefully selecting and preparing the host image, users can significantly enhance the security and undetectability of the embedded data. SecretPixel leverages these principles to ensure that your sensitive information remains hidden from prying eyes and sophisticated steganalysis methods.

## Collaboration

We welcome contributions from the community! If you'd like to collaborate on this project, you can do so in several ways:

- **Reporting Issues**: If you find a bug or have a suggestion for improving the project, please use the [Issues](https://github.com/x011/SecretPixel/issues) section to report them.

- **Submitting Pull Requests**: If you've made improvements to the project and would like to share them, please submit a [Pull Request](https://github.com/x011/SecretPixel/pulls) with a clear description of your changes.

- **Feature Requests**: Have an idea for a new feature? Feel free to submit it as an issue, and we can discuss it together.

- **Documentation**: Help us improve the documentation by fixing typos, adding examples, or clarifying sections that are unclear.

We look forward to your contributions and are excited to see what we can build together!

## Conclusion

SecretPixel is a unique and highly secure steganography tool that offers advanced features for anyone needing to protect and conceal sensitive data within images. Its robust encryption, compression, and evasion techniques make it an excellent choice for users who require the utmost in security and privacy.

## License

This program is released under the GNU General Public License v3.0.

For more details, see the [LICENSE](https://github.com/x011/SecretPixel?tab=GPL-3.0-1-ov-file) file or visit [GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.en.html).
