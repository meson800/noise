#include "Helpers.h"

unsigned int Helpers::bytesToUINT(const unsigned char * bytes)
{
	return ( (bytes[0] << 24) + (bytes[1] << 16) + (bytes[2] << 8) + bytes[3]);
}

std::vector<unsigned char> Helpers::uintToBytes(unsigned int num)
{
	std::vector<unsigned char> result;

	uintToBytes(num, result);
	return result;
}

void Helpers::uintToBytes(unsigned int num, std::vector<unsigned char>& bytes)
{
	//push back first four bytes for keysize
	bytes.push_back((num >> 24) & 0xFF);
	bytes.push_back((num >> 16) & 0xFF);
	bytes.push_back((num >> 8) & 0xFF);
	bytes.push_back(num & 0xFF);
}

void Helpers::insertVector(std::vector<unsigned char>& dest, const std::vector<unsigned char>& source)
{
	for (unsigned int i = 0; i < source.size(); ++i)
		dest.push_back(source[i]);
}
