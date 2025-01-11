#pragma once
#include <string>

class Encryptor {
public:
	static std::string encrypt(const std::string &plaintext, const std::string &key);
};