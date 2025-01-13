<<<<<<< HEAD
#ifndef KEYMANAGER_H
#define KEYMANAGER_H

=======
// keymanager.h
#pragma once
>>>>>>> 84501201364922e8ffda41cbc00677c708e74c21
#include <string>

class KeyManager {
public:
<<<<<<< HEAD
	static std::string generateKey();  // Generates a random 32-byte AES-256 key
	static std::string deriveKey(const std::string& password, const std::string& salt);  // PBKDF2 key derivation
};

#endif
=======
	static std::string generateKey();
};
>>>>>>> 84501201364922e8ffda41cbc00677c708e74c21
