#include "encryptor.h"
#include "decryptor.h"
#include "keymanager.h"
#include "logger.h"

int main() {
	Logger::log("SecureCryptoProject Started.");
	std::string plaintext = "Hello, Secure World!";
	std::string key = KeyManager::generateKey();
	std::string encrypted = Encryptor::encrypt(plaintext, key);
	std::string decrypted = Decryptor::decrypt(encrypted, key);
	Logger::log("Decrypted text: " + decrypted);
	return 0;
}