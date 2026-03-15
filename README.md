# SecureCrypto

[![CI](https://github.com/jazicate/SecureCrypto/actions/workflows/ci.yml/badge.svg)](https://github.com/jazicate/SecureCrypto/actions/workflows/ci.yml)

`securecrypto` is a small C++ command-line tool for encrypting files and directories with a password.

It uses:

- AES-256-GCM for authenticated encryption
- `scrypt` for password-based key derivation
- a simple binary envelope that stores the salt, nonce, tag, and KDF parameters next to the ciphertext

The code is in no-man's-land between demo and real utility: it is much better than the original ECB string example, but it is still intentionally small and easy to read.

## Commands
```bash
securecrypto encrypt --in <file|dir> --out <file|dir> [--password <secret>]
securecrypto decrypt --in <file|dir> --out <file|dir> [--password <secret>]
securecrypto inspect --in <file>
```

If `--password` is omitted, the tool prompts on the terminal. `encrypt` asks for confirmation; `decrypt` does not.

## What It Actually Does
- Encrypts a single file to a single output file
- Decrypts a single encrypted file to a single output file
- Recursively encrypts directory trees
- Recursively decrypts directory trees
- Streams file contents in chunks instead of loading the whole file into memory
- Refuses to produce plaintext output if GCM authentication fails

For directory mode:

- encrypted files get a `.enc` suffix
- decrypted files have `.enc` stripped when possible
- relative paths are preserved under the output directory

## Envelope Layout
Each encrypted file starts with a small header, followed by ciphertext.

Header fields:
- magic bytes: `SCRYPT01`
- format version
- plaintext size
- ciphertext size
- `scrypt` parameters: `N`, `r`, `p`, `maxmem`
- random salt
- random nonce
- GCM authentication tag

The `inspect` command prints those fields without decrypting the file.

## Build
Requirements:
- C++17 compiler
- CMake 3.20+
- OpenSSL development files
- Catch2 3.x for tests

macOS with Homebrew:

```bash
brew install openssl catch2
cmake -S . -B build \
  -DOPENSSL_ROOT_DIR="$(brew --prefix openssl)" \
  -DCMAKE_PREFIX_PATH="$(brew --prefix catch2);$(brew --prefix openssl)"
cmake --build build
```

Linux:

```bash
sudo apt-get install libssl-dev catch2
cmake -S . -B build
cmake --build build
```

## Usage
Encrypt a file:

```bash
./bin/securecrypto encrypt --in notes.txt --out notes.txt.enc
```

Decrypt it:

```bash
./bin/securecrypto decrypt --in notes.txt.enc --out notes.txt
```

Inspect the metadata:

```bash
./bin/securecrypto inspect --in notes.txt.enc
```

Encrypt a directory tree:

```bash
./bin/securecrypto encrypt --in ./docs --out ./docs.enc
```

Decrypt it back:

```bash
./bin/securecrypto decrypt --in ./docs.enc --out ./docs.restored
```

## Tests
The test target uses Catch2 and currently covers:

- single-file round trips
- empty files
- multi-megabyte streamed files
- recursive directory handling
- invalid envelope rejection
- wrong-password failures
- tamper detection
- missing-path and empty-password validation

Run the suite with:

```bash
ctest --test-dir build --output-on-failure
```

## Limitations
This is still a small tool. Notable gaps:

- no Windows password prompt support
- no progress reporting
- no include/exclude rules for recursive mode
- no keychain or external key management integration
- no compatibility promise for future envelope changes
