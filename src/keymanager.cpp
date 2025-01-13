#include "keymanager.h"
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdexcept>
#include <vector>

#define AES_BLOCK_SIZE 32  // AES-256 requires 32-byte keys

/**
 * Generates a random 32-byte AES-256 key using OpenSSL's RAND_bytes.
 *
 * @return A 32-byte key as a string.
 * @throws std::runtime_error if the random key generation fails.
 */
std::string KeyManager::generateKey() {
	// Generate a random 32-byte key for AES-256
	std::vector<unsigned char> key(AES_BLOCK_SIZE);
	if (RAND_bytes(key.data(), AES_BLOCK_SIZE) != 1) {
		throw std::runtime_error("Failed to generate random key.");
	}

	return std::string(reinterpret_cast<const char*>(key.data()), AES_BLOCK_SIZE);
}

/**
 * Derives a 32-byte key from a given password and salt using OpenSSL's PBKDF2.
 *
 * @param password The password to use for key derivation.
 * @param salt The salt value to use for key derivation.
 * @return A 32-byte key as a string.
 * @throws std::runtime_error if the key derivation fails.
 */
std::string KeyManager::deriveKey(const std::string& password, const std::string& salt) {
	// PBKDF2 to derive a key from the password and salt
	std::vector<unsigned char> key(AES_BLOCK_SIZE);  // AES-256 key size
	if (PKCS5_PBKDF2_HMAC(password.c_str(), password.length(), reinterpret_cast<const unsigned char*>(salt.c_str()), salt.length(), 10000, EVP_sha256(), AES_BLOCK_SIZE, key.data()) != 1) {
		throw std::runtime_error("Failed to derive key using PBKDF2.");
	}

	return std::string(reinterpret_cast<const char*>(key.data()), AES_BLOCK_SIZE);
}
