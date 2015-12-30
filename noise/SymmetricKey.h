#pragma once

#include <vector>
#include <string>

struct SymmetricKey
{
	std::vector<unsigned char> key;
	std::vector<unsigned char> iv;

	std::string toString() const;
};