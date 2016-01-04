#pragma once
#include <vector>
#include "Fingerprint.h"
#include <string>

struct Message
{
	Fingerprint to;
	Fingerprint from;
	std::vector<unsigned char> message;
	std::string toString();
};