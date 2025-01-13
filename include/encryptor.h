#ifndef ENCRYPTOR_H
#define ENCRYPTOR_H

#include <string>

extern int AES_BLOCK_SIZE;

class Encryptor {
public:
	static std::string encrypt(const std::string &plaintext, const std::string &key);
};

#endif
