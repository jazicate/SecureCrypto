#include "encryptor.h"
#include "decryptor.h"
#include "keymanager.h"
#include "logger.h"
<<<<<<< HEAD
#include <openssl/rand.h>
#include <vector>
#include <stdexcept>

/**
 * The main function of the SecureCryptoProject application.
 * 
 * This function performs the following operations:
 * 1. Logs the start of the application.
 * 2. Sets a secure password for key derivation.
 * 3. Generates a random 16-byte salt.
 * 4. Logs the successful generation of the salt.
 * 5. Derives an AES key using the password and generated salt.
 * 6. Logs the successful derivation of the key.
 * 7. Encrypts a plaintext message using the derived key.
 * 8. Decrypts the ciphertext back to the original plaintext.
 * 9. Logs the decrypted text.
 */
int main() {
	Logger::log("SecureCryptoProject Started.");
	
	// Password for key derivation
	std::string password = "my_secure_password";
	
	// Generate a random 16-byte salt (you can use any length you like)
	std::vector<unsigned char> salt(16);
	if (RAND_bytes(salt.data(), salt.size()) != 1) {
		throw std::runtime_error("Failed to generate random salt.");
	}
	std::string saltStr(reinterpret_cast<char*>(salt.data()), salt.size());

	Logger::log("Random salt generated successfully.");
	
	// Derive the AES key from the password and salt
	std::string key = KeyManager::deriveKey(password, saltStr);
	
	Logger::log("Key derived successfully.");
	
	std::string plaintext = "Hello, Secure World!";
	
	// Encrypt the plaintext with the derived key
	std::string encrypted = Encryptor::encrypt(plaintext, key);
	
	// Decrypt the ciphertext with the same derived key
	std::string decrypted = Decryptor::decrypt(encrypted, key);
	
	Logger::log("Decrypted text: " + decrypted);
	
	return 0;
}
=======

int main() {
	Logger::log("SecureCryptoProject Started.");
	std::string plaintext = "Hello, Secure World!";
	std::string key = KeyManager::generateKey();
	std::string encrypted = Encryptor::encrypt(plaintext, key);
	std::string decrypted = Decryptor::decrypt(encrypted, key);
	Logger::log("Decrypted text: " + decrypted);
	return 0;
}
>>>>>>> 84501201364922e8ffda41cbc00677c708e74c21
