#pragma once

#include <vector>
#include <map>
#include <mutex>

#include "Envelope.h"
#include "SymmetricKey.h"

namespace openssl
{
	struct evp_pkey_ctx_st;
	typedef evp_pkey_ctx_st EVP_PKEY_CTX;

	struct evp_pkey_st;
	typedef evp_pkey_st EVP_PKEY;
}

class Crypto
{
public:
	//Initalizes the random pool and generates parameters for key generation
	Crypto();
	~Crypto();
	void generateKeypair(openssl::EVP_PKEY** key);
	void generateEphemeralKeypair(openssl::EVP_PKEY** key);
	std::vector<unsigned char> signMessage(openssl::EVP_PKEY* key, const std::vector<unsigned char>& message);
	bool verifySignature(openssl::EVP_PKEY* key, const std::vector<unsigned char>& message, const std::vector<unsigned char>& signature);
	//Derive a shared key and IV based on two ephemeral keys. This function deallocates the keys afterwards
	void deriveSharedKey(openssl::EVP_PKEY * key, openssl::EVP_PKEY * otherKey,
		SymmetricKey& sharedKey);
	//Encrypt plaintext with a given key and IV
	std::vector<unsigned char> encryptSymmetric(const SymmetricKey& key, const std::vector<unsigned char>& plaintext);
	//Decrypt ciphertext with a given key and IV
	std::vector<unsigned char> decryptSymmetric(const SymmetricKey& key, const std::vector<unsigned char>& ciphertext);

	//Asymmetric encryption------------------
	//Encrypt plaintext with a publickey
	Envelope encryptAsymmetric(openssl::EVP_PKEY** publicKey, std::vector<unsigned char> plaintext);
	//Decrypt an envelope
	std::vector<unsigned char> decryptAsymmetric(openssl::EVP_PKEY* key, const Envelope& envelope);

	//Generate symmetric key from password
	//Salt should be 8 bytes long, and randomly generated
	SymmetricKey deriveKeyFromPassword(const std::vector<unsigned char>& salt, const std::vector<unsigned char>& password);

	static std::map<int, std::mutex> cryptoMuxes;

private:
	openssl::EVP_PKEY_CTX* keyContext;

	openssl::EVP_PKEY_CTX* ephemeralParamContext;
	openssl::EVP_PKEY_CTX* ephemeralKeyContext;
	openssl::EVP_PKEY* ephemeralKeyParams;

};
