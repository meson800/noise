#pragma once

#include <vector>
#include <string>

//forward declarations
namespace openssl
{
	struct evp_pkey_st;
	typedef evp_pkey_st EVP_PKEY;
}
namespace RakNet
{
	class BitStream;
}

class Fingerprint
{
public:
	//calculates fingerprint of given key
	Fingerprint(openssl::EVP_PKEY* key);
	Fingerprint(RakNet::BitStream& bs);
	Fingerprint(std::vector<unsigned char> _data);
	//Returns fingerprint in human readable form
	std::string toString() const;
	void toBitStream(RakNet::BitStream& bs) const;

	//operators
	Fingerprint& operator=(const Fingerprint &other);
	bool operator<(const Fingerprint &other) const;
	bool operator==(const Fingerprint &other) const;
	bool operator!=(const Fingerprint &other) const;
	std::vector<unsigned char> data;

};