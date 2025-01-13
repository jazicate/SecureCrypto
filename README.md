# SecureCryptoProject

The **SecureCryptoProject** is a C++ application that demonstrates the use of AES-256 encryption and decryption using OpenSSL. The project allows you to encrypt and decrypt messages using a derived AES key, either generated randomly or derived from a password and salt. The project also includes basic tests for encryption, decryption, key generation, and edge cases using Catch2.

## Features

- AES-256 encryption and decryption in ECB mode.
- Key generation using OpenSSL's `RAND_bytes`.
- Key derivation using PBKDF2 with a password and salt.
- Simple logging system for tracing operations.
- Catch2-based tests for basic functionality and edge cases.

## Requirements

Before building the project, ensure you have the following installed:

- **C++17** compliant compiler (e.g., GCC, Clang, MSVC).
- **CMake** (version 3.10 or above).
- **OpenSSL** (version 1.1.1 or above).
- **Catch2** for testing (automatically fetched using CMake).

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/SecureCryptoProject.git
cd SecureCryptoProject
```

### 2. Install Dependencies
Make sure you have OpenSSL installed. On a Linux system, you can install it via:
```bash
sudo apt-get install libssl-dev
```
On macOS, use HomeBrew:
```bash
brew install openssl
```

### 3. Build the Project
Create a build directory and use CMake to configure and build the project:
```bash
cd build
cmake ..
cmake --build .
```
### 4. Running the Application
Run the application by executing the compiled executable:
```bash
./bin/SecureCryptoProject
```

### 5. Running Tests (subject to more tests in the future)
To run tests for the project, use the following commands:
```bash
cd build
make TestProject
./TestProject (in bin)
```
Alternatively, you can run the tests using CTest:
```bash
ctest
```

## Security Considerations
- **AES-256 in ECB Mode:** ECB mode is used here for simplicity. For enhanced security, consider using AES with a mode like CBC or GCM, which includes an initialization vector (IV) and provides better security by ensuring identical plaintext blocks don't result in identical ciphertext blocks.
- **Key Management:** The project demonstrates how to derive keys from a password and salt using PBKDF2, which is suitable for many use cases. However, in production systems, more advanced key management and protection methods should be employed.
- **Padding:** The project uses zero-padding for AES encryption. Make sure to consider proper padding schemes like PKCS7 for robust production use.
