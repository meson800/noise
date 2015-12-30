#pragma once
#include <vector>

class Envelope
{
public:
	Envelope();
	Envelope(const std::vector<unsigned char>& data);
	std::vector<unsigned char> toBytes();

	std::vector<unsigned char> sessionKey;
	std::vector<unsigned char> iv;
	std::vector<unsigned char> ciphertext;
};
