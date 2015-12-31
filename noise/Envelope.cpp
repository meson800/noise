#include "Envelope.h"

Envelope::Envelope() {}

Envelope::Envelope(const std::vector<unsigned char>& data)
{
	//see if it has at least 256 + 128 bytes
	if (data.size() < 256 + 128)
		throw std::runtime_error("Data too small to create envelope");

	//First four bytes define keysize
	int keySize = (data[0] << 24) + (data[1] << 16) + (data[2] << 8) + data[3];

	//extract session key
	for (unsigned int i = 4; i < 4 + (unsigned int)keySize; ++i)
		sessionKey.push_back(data[i]);
	//extract iv
	for (unsigned int i = 4 + keySize; i < 4 + (unsigned int)keySize + 128; ++i)
		iv.push_back(data[i]);
	//and extract ciphertext
	for (unsigned int i = 4 + (unsigned int)keySize + 128; i < data.size(); ++i)
		ciphertext.push_back(data[i]);
}

std::vector<unsigned char> Envelope::toBytes()
{
	std::vector<unsigned char> result;
	int keySize = sessionKey.size();

	//push back first four bytes for keysize
	result.push_back((keySize >> 24) & 0xFF);
	result.push_back((keySize >> 16) & 0xFF);
	result.push_back((keySize >> 8) & 0xFF);
	result.push_back(keySize & 0xFF);

	//then pushback key
	for (unsigned int i = 0; i < (unsigned int)keySize; ++i)
		result.push_back(sessionKey[i]);
	//then pushback iv (always 16 bytes)
	for (unsigned int i = 0; i < 16; ++i)
		result.push_back(iv[i]);
	//then pushback ciphertext
	for (unsigned int i = 0; i < ciphertext.size(); ++i)
		result.push_back(ciphertext[i]);

	return result;
}
