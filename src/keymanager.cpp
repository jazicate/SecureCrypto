#include "keymanager.h"
#include <openssl/rand.h>
#include <stdexcept>
#include <string>
#include <vector>

#define AES_BLOCK_SIZE 16 

std::string KeyManager::generateKey() {
	// Generate a random 16-byte key
	std::vector<unsigned char> key(AES_BLOCK_SIZE);
	if (RAND_bytes(key.data(), AES_BLOCK_SIZE) != 1) {
		throw std::runtime_error("Failed to generate random key.");
	}

	return std::string(reinterpret_cast<const char *>(key.data()), AES_BLOCK_SIZE);
}
