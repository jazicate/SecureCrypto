#include "encryptor.h"
#include <openssl/evp.h>
#include <stdexcept>
#include <vector>
#include <cstring>  // For memcpy
#include "logger.h"

#define AES_BLOCK_SIZE 16 // Define AES_BLOCK_SIZE as 16 bytes

std::string Encryptor::encrypt(const std::string &plaintext, const std::string &key) {
	if (key.size() != AES_BLOCK_SIZE) {
		throw std::invalid_argument("Key length must be 16 bytes.");
	}

	// Initialize OpenSSL (if needed for older versions)
	OpenSSL_add_all_algorithms();  // Ensure OpenSSL is initialized for cipher algorithms

	// Create and initialize the context for encryption
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		throw std::runtime_error("Failed to create EVP context.");
	}
	// Logger::log("EVP context created.");

	// Initialize encryption with AES-128 in ECB mode
	if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, reinterpret_cast<const unsigned char*>(key.c_str()), nullptr) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		throw std::runtime_error("Failed to initialize encryption.");
	}
	// Logger::log("Encryption initialized.");

	// Ensure the plaintext length is a multiple of AES_BLOCK_SIZE by padding
	size_t paddedLength = (plaintext.size() / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;
	std::vector<unsigned char> paddedText(paddedLength, 0);  // Pad with zeros
	std::memcpy(paddedText.data(), plaintext.data(), plaintext.size());

	// Allocate enough space for the ciphertext, including potential padding
	std::vector<unsigned char> ciphertext(paddedLength + AES_BLOCK_SIZE);
	int len = 0;
	if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, paddedText.data(), paddedText.size()) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		throw std::runtime_error("Encryption failed during update.");
	}
	// Logger::log("Encryption update completed.");

	// Finalize the encryption
	int finalLen = 0;
	if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &finalLen) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		throw std::runtime_error("Encryption finalization failed.");
	}

	EVP_CIPHER_CTX_free(ctx);
	// Logger::log("EVP context freed.");

	// Adjust the final size of ciphertext
	ciphertext.resize(len + finalLen);
	// Logger::log("Ciphertext size after resize: " + std::to_string(ciphertext.size()));

	// Return the encrypted data as a string (raw bytes, not null-terminated)
	return std::string(reinterpret_cast<char*>(ciphertext.data()), ciphertext.size());
}