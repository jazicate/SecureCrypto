#ifndef DECRYPTOR_H
#define DECRYPTOR_H

#include <string>

extern int AES_BLOCK_SIZE;

class Decryptor {
public:
	static std::string decrypt(const std::string &ciphertext, const std::string &key);
};

#endif
