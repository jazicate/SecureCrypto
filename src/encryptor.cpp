#include "encryptor.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <stdexcept>
#include <vector>
#include <cstring>
#include <openssl/err.h>

#define AES_BLOCK_SIZE 32  // AES-256 requires 32-byte keys

	/**
	 * Encrypts a given string using AES-256 in ECB mode. The key must be
	 * 32 bytes long, or an std::invalid_argument exception will be thrown.
	 *
	 * @param plaintext The string to be encrypted.
	 * @param key The 32-byte key to use for encryption.
	 * @return The encrypted ciphertext as a string.
	 */
std::string Encryptor::encrypt(const std::string &plaintext, const std::string &key) {
	if (key.size() != AES_BLOCK_SIZE) {
		throw std::invalid_argument("Key length must be 32 bytes for AES-256.");
	}

	// Initialize OpenSSL (if needed for older versions)
	OpenSSL_add_all_algorithms();

	// Create and initialize the context for encryption
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		throw std::runtime_error("Failed to create EVP context.");
	}

	// Initialize encryption with AES-256 in ECB mode
	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), nullptr, reinterpret_cast<const unsigned char*>(key.c_str()), nullptr) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		throw std::runtime_error("Failed to initialize encryption.");
	}

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

	// Finalize the encryption
	int finalLen = 0;
	if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &finalLen) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		throw std::runtime_error("Encryption finalization failed.");
	}

	EVP_CIPHER_CTX_free(ctx);

	// Adjust the final size of ciphertext
	ciphertext.resize(len + finalLen);

	return std::string(reinterpret_cast<char*>(ciphertext.data()), ciphertext.size());
}
