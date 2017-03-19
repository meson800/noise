#pragma once

#include <random>

class RandomHelpers
{
public:
	static uint64_t GenerateGUID(void);

private:
	static std::random_device rd;
	static std::mt19937_64 mt;
	static std::uniform_int_distribution<uint64_t> dist;

};
