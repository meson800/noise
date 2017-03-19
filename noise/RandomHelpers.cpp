#include "RandomHelpers.h"

std::random_device RandomHelpers::rd;
std::mt19937_64 RandomHelpers::mt = std::mt19937_64(RandomHelpers::rd());
std::uniform_int_distribution<uint64_t> RandomHelpers::dist;

uint64_t RandomHelpers::GenerateGUID(void)
{
	return dist(mt);
}
