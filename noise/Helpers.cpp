#include "Helpers.h"
#ifdef WIN32
#include <windows.h>
#else
#include <time.h>
#endif

#include "Log.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <stdexcept>

unsigned int Helpers::bytesToUINT(const unsigned char * bytes)
{
	return ( (bytes[0] << 24) + (bytes[1] << 16) + (bytes[2] << 8) + bytes[3]);
}

uint64_t Helpers::bytesToUINT64(const unsigned char * bytes)
{
	return ( (static_cast<uint64_t>(bytes[0]) << 56) + (static_cast<uint64_t>(bytes[1]) << 48) 
		+ (static_cast<uint64_t>(bytes[2]) << 40) + (static_cast<uint64_t>(bytes[3]) << 32)
		+ (static_cast<uint64_t>(bytes[4]) << 24) + (static_cast<uint64_t>(bytes[5]) << 16)
		+ (static_cast<uint64_t>(bytes[6]) << 8) + static_cast<uint64_t>(bytes[7]));
}

std::vector<unsigned char> Helpers::uint64ToBytes(uint64_t num)
{
	std::vector<unsigned char> result;
	result.push_back((num >> 56) & 0xFF);
	result.push_back((num >> 48) & 0xFF);
	result.push_back((num >> 40) & 0xFF);
	result.push_back((num >> 32) & 0xFF);
	result.push_back((num >> 24) & 0xFF);
	result.push_back((num >> 16) & 0xFF);
	result.push_back((num >> 8) & 0xFF);
	result.push_back(num & 0xFF);
	
	return result;
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

void Helpers::sleep_ms(unsigned int ms)
{
#ifdef WIN32
	Sleep(ms);
#else
	struct timespec ts;
	ts.tv_sec = ms / 1000;
	ts.tv_nsec = (ms % 1000) * 1000 * 1000;
	nanosleep(&ts, NULL);
#endif
}

void Helpers::writeToFd(int fd, const std::vector<unsigned char>& bytes)
{
	int cur_index = 0;
	while (cur_index < bytes.size())
	{
		int result = write(fd, bytes.data() + cur_index, bytes.size() - cur_index);
		if (result == -1)
		{
			Log::writeToLog(Log::ERR, "Write to fd ", fd, "failed with error ", strerror(errno));
			throw std::runtime_error("Write threw an exception");
		}
		cur_index += result;
	}
}
			
	

std::vector<unsigned char> Helpers::stringToBytes(const std::string & str)
{
	std::vector<unsigned char> result;
	for (unsigned int i = 0; i < str.size(); ++i)
		result.push_back((unsigned char)str[i]);
	return result;
}

void Helpers::insertVector(std::vector<unsigned char>& dest, const std::vector<unsigned char>& source)
{
	for (unsigned int i = 0; i < source.size(); ++i)
		dest.push_back(source[i]);
}
