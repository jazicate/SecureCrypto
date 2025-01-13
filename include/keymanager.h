#ifndef KEYMANAGER_H
#define KEYMANAGER_H

#include <string>

class KeyManager {
public:
	static std::string generateKey();  // Generates a random 32-byte AES-256 key
	static std::string deriveKey(const std::string& password, const std::string& salt);  // PBKDF2 key derivation
};

#endif
