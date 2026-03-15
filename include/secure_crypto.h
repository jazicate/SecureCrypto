#ifndef SECURE_CRYPTO_H
#define SECURE_CRYPTO_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace securecrypto {

// These are the scrypt cost parameters written into each encrypted file.
// Keeping them in the header lets decryption know how the key was derived.
struct ScryptParams {
    uint64_t n = 1u << 15;
    uint64_t maxMemoryBytes = 64ull * 1024ull * 1024ull;
    uint32_t r = 8;
    uint32_t p = 1;
};

// Metadata stored in the encrypted file header before the ciphertext bytes.
struct FileMetadata {
    uint8_t version = 1;
    uint64_t plaintextSize = 0;
    uint64_t ciphertextSize = 0;
    ScryptParams scrypt;
    std::vector<unsigned char> salt;
    std::vector<unsigned char> nonce;
    std::vector<unsigned char> tag;
};

// A small summary returned after recursive directory operations.
struct PathStats {
    size_t filesProcessed = 0;
    size_t directoriesProcessed = 0;
};

// Helper functions used by the tests and by some of the file-format code.
std::vector<unsigned char> readFile(const std::string& path);
void writeFile(const std::string& path, const std::vector<unsigned char>& data);

// Single-file helpers.
void encryptFile(const std::string& inputPath, const std::string& outputPath, const std::string& password);
void decryptFile(const std::string& inputPath, const std::string& outputPath, const std::string& password);

// File-or-directory helpers used by the CLI.
PathStats encryptPath(const std::string& inputPath, const std::string& outputPath, const std::string& password);
PathStats decryptPath(const std::string& inputPath, const std::string& outputPath, const std::string& password);

// Reads only the header information; it does not decrypt the payload.
FileMetadata inspectFile(const std::string& path);

// Used by the inspect command to print binary values in a readable form.
std::string toHex(const std::vector<unsigned char>& bytes);

}  // namespace securecrypto

#endif
