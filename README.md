Advanced Encryption Tool
A secure command-line encryption/decryption tool written in C, utilizing modern cryptographic primitives and advanced features for robust data protection.
Features

Symmetric Encryption: Uses AES-128-GCM for secure encryption.
Key Derivation: Employs Argon2id for secure key derivation from passwords.
Integrity Protection: Implements HMAC-SHA256 for data integrity verification.
Compression: Optional zlib compression to reduce message size before encryption.
Block-Based Encryption: Processes messages in fixed-size blocks for enhanced security.
Multiple Passes: Applies encryption multiple times (default: 3 passes) for increased complexity.
Dynamic Offsets: Uses position, length, and timestamp-based offsets for transformations.
Unicode Support: Handles UTF-8 encoded input for broad character compatibility.
Salt and Padding: Adds random salt and configurable padding to obscure patterns and length.
Substitution Tables: Applies non-linear transformations via shuffled substitution tables.
Time-Based Variations: Incorporates timestamp for time-dependent encryption.
Error Handling: Comprehensive error codes and messages for robust operation.
Performance Optimized: Efficient buffer management for large messages (up to 1MB).

Dependencies

OpenSSL (libcrypto): For AES-GCM encryption, HMAC, and random number generation.
zlib: For compression/decompression.
Argon2: For secure key derivation.

On Ubuntu/Debian, install dependencies with:
sudo apt-get install libssl-dev zlib1g-dev libargon2-dev

Compilation
Compile the source code (crypto.c) using GCC:
gcc -o crypto crypto.c -lcrypto -lz -largon2

Ensure the dependencies are installed and linked correctly.
Usage
Run the compiled binary to encrypt or decrypt messages:
./crypto

The tool prompts for the following inputs:

Mode: Enter encrypt or decrypt.
Message: The text to encrypt or the base64-encoded encrypted data to decrypt.
Key: The secret key (password) for encryption/decryption.
Padding Length: Number of padding bytes (0-128, default: 16).
Compression: Enable compression (y for yes, n for no, default: yes).

Example: Encryption
$ ./crypto
Advanced Encryption Tool
Mode (encrypt/decrypt): encrypt
Message: Hello, World!
Key: mysecretkey
Padding length (0-128, default 16): 16
Use compression? (y/n, default y): y
Encrypted (base64): AQ... (base64 output)

Example: Decryption
$ ./crypto
Advanced Encryption Tool
Mode (encrypt/decrypt): decrypt
Message: AQ... (base64 input)
Key: mysecretkey
Padding length (0-128, default 16): 16
Use compression? (y/n, default y): y
Decrypted: Hello, World!

Security Notes

Key Management: Store keys securely. Do not hardcode or expose keys.
Input Validation: Ensure the key and message are non-empty. Maximum message length is 1MB.
Padding: Use padding (0-128 bytes) to obscure message length.
Versioning: Supports version "01". Ensure compatibility when decrypting.
Error Handling: Check error messages for issues like invalid keys or tampered data.

Limitations

Maximum message length: 1MB to prevent excessive memory usage.
UTF-8 encoding is assumed for input messages.
Compression may not significantly reduce size for small or already compressed data.

Building and Running on Other Platforms

macOS: Install dependencies via Homebrew (brew install openssl zlib argon2) and compile with appropriate library paths.
Windows: Use a Cygwin/MinGW environment or cross-compile, ensuring OpenSSL, zlib, and Argon2 libraries are available.

License
This project is licensed under the MIT License.
Contributing
Contributions are welcome! Please submit pull requests or open issues on the project repository
Contact
For questions or support, contact the maintainer at jlfernandez@mmsu.edu.ph or file an issue on the project repository.
# next-letter-encryption
