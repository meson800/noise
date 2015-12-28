#pragma once
#include <vector>

namespace openssl
{
	struct evp_pkey_st;
	typedef evp_pkey_st EVP_PKEY;
}

struct CryptoHelpers
{
	static std::vector<unsigned char> oslPublicKeyToBytes(openssl::EVP_PKEY* key);
	static openssl::EVP_PKEY* bytesToOslPublicKey(const std::vector<unsigned char>& bytes);
};