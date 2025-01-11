#pragma once
#include <string>

class Decryptor {
public:
	static std::string decrypt(const std::string &ciphertext, const std::string &key);
};