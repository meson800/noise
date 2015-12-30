#include "SymmetricKey.h"

std::string SymmetricKey::toString() const
{
	std::string result = std::string(8 + key.size() + iv.size(), ' ');
	result[0] = 'K'; result[1] = 'e'; result[2] = 'y'; result[3] = ':';

	for (unsigned int i = 0; i < key.size(); ++i)
		result[4 + i] = key[i];

	result[4 + key.size()] = ' '; result[4 + key.size() + 1] = 'I';
	result[4 + key.size() + 2] = 'v'; result[4 + key.size() + 3] = ':';

	for (unsigned int i = 0; i < iv.size(); ++i)
		result[8 + key.size() + i] = iv[i];

	return result;
}
