#pragma once

#include <vector>
#include <string>

class Helpers
{
public:
	static unsigned int bytesToUINT(const unsigned char* bytes);
	static std::vector<unsigned char> uintToBytes(unsigned int num);
	static uint64_t bytesToUINT64(const unsigned char* bytes);
	static std::vector<unsigned char> uint64ToBytes(uint64_t num);
	static void uintToBytes(unsigned int num, std::vector<unsigned char>& bytes);
	static std::vector<unsigned char> stringToBytes(const std::string& str);
	static void sleep_ms(unsigned int ms);
	static void writeToFd(int fd, const std::vector<unsigned char>& bytes);

	//Copy functions
	static void insertVector(std::vector<unsigned char>& dest, const std::vector<unsigned char>& source);

};
