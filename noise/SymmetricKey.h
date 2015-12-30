#pragma once

#include <vector>

struct SymmetricKey
{
	std::vector<unsigned char> key;
	std::vector<unsigned char> iv;
};