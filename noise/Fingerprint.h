#pragma once

#include <vector>
#include <string>

//forward declarations
namespace openssl
{
	struct evp_pkey_st;
	typedef evp_pkey_st EVP_PKEY;
}

class Fingerprint
{
public:
	//calculates fingerprint of given key
	Fingerprint(openssl::EVP_PKEY* key);
	//Returns fingerprint in human readable form
	std::string toString();

	//operators
	Fingerprint& operator=(const Fingerprint &other);
	bool operator<(const Fingerprint &other) const;
	bool operator==(const Fingerprint &other) const;
	bool operator!=(const Fingerprint &other) const;
	std::vector<unsigned char> data;

};