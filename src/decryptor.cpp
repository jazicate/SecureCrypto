#include "decryptor.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <stdexcept>
#include <vector>
#include <cstring>
#include <openssl/err.h>

#define AES_BLOCK_SIZE 32

/**
 * Decrypts a given string using AES-256 in ECB mode. The key must be
 * 32 bytes long, or an std::invalid_argument exception will be thrown.
 *
 * @param ciphertext The string to be decrypted.
 * @param key The 32-byte key to use for decryption.
 * @return The decrypted plaintext as a string.
 * @throws std::invalid_argument if the key length is not 32 bytes.
 * @throws std::runtime_error if decryption fails at any stage.
 */

std::string Decryptor::decrypt(const std::string &ciphertext, const std::string &key) {
	if (key.size() != AES_BLOCK_SIZE) {
		throw std::invalid_argument("Key length must be 32 bytes for AES-256.");
	}

	// Initialize OpenSSL (if needed for older versions)
	OpenSSL_add_all_algorithms();

	// Create and initialize the context for decryption
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		throw std::runtime_error("Failed to create EVP context.");
	}

	// Initialize decryption with AES-256 in ECB mode
	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), nullptr, reinterpret_cast<const unsigned char*>(key.c_str()), nullptr) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		throw std::runtime_error("Failed to initialize decryption.");
	}

	// Convert the ciphertext string to a vector of unsigned chars for decryption
	std::vector<unsigned char> cipherData(ciphertext.begin(), ciphertext.end());
	size_t cipherLength = cipherData.size();

	// Allocate space for the plaintext (same size as ciphertext)
	std::vector<unsigned char> plaintext(cipherLength);

	int len = 0;
	if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, cipherData.data(), cipherLength) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		throw std::runtime_error("Decryption failed during update.");
	}

	// Finalize the decryption
	int finalLen = 0;
	if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &finalLen) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		throw std::runtime_error("Decryption finalization failed.");
	}

	EVP_CIPHER_CTX_free(ctx);

	// Resize the plaintext buffer to the correct length
	plaintext.resize(len + finalLen);

	// Convert the decrypted data to a string (null-terminated)
	std::string decrypted(reinterpret_cast<char*>(plaintext.data()), plaintext.size());

	// Remove padding if needed
	size_t end = decrypted.find('\0');
	if (end != std::string::npos) {
		decrypted = decrypted.substr(0, end);  // Remove the null padding
	}

	return decrypted;
}
