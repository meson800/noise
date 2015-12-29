#include "Crypto.h"
#include "Exceptions.h"
#include "Log.h"

namespace openssl {
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/rsa.h>
#include <openssl/opensslconf.h>
#include <openssl/conf.h>
#include <openssl/err.h>

}

Crypto::Crypto()
{
	Log::writeToLog(Log::INFO, "Initalizing crypto...");
	//init openssl
	openssl::ERR_load_crypto_strings();
	openssl::OpenSSL_add_all_algorithms();
	openssl::OPENSSL_config(NULL);
	//seed random number generator
	openssl::RAND_poll();

	if (!(keyContext = openssl::EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL)))
		throw OpensslException("Can't create key generation context");
	//init key generation
	if (!openssl::EVP_PKEY_keygen_init(keyContext))
		throw OpensslException("Can't initalize key generation");
	if (!openssl::EVP_PKEY_CTX_set_rsa_keygen_bits(keyContext, 4096))
		throw OpensslException("Can't set number of bits in RSA key");
	Log::writeToLog(Log::INFO, "Done initalizing crypto");
}

Crypto::~Crypto()
{
	//free contexts
	openssl::EVP_PKEY_CTX_free(keyContext);
}

void Crypto::generateKeypair(openssl::EVP_PKEY ** key)
{
	Log::writeToLog(Log::INFO, "Generating RSA keypair");
	if (!keyContext)
		throw KeyGenerationException("Can't generate keypair, no key context");
	if (!openssl::EVP_PKEY_keygen(keyContext, key))
		throw KeyGenerationException("Key generation failed");
}

std::vector<unsigned char> Crypto::signMessage(openssl::EVP_PKEY * key, const std::vector<unsigned char>& message)
{
	openssl::EVP_MD_CTX* digestContext = 0;
	//create and init the context
	if (!(digestContext = openssl::EVP_MD_CTX_create()))
		throw OpensslException("Couldn't create message signing context");
	if (1 != openssl::EVP_DigestSignInit(digestContext, NULL, openssl::EVP_sha256(), NULL, key))
		throw OpensslException("Couldn't init message signing");

	//sign message
	if (1 != openssl::EVP_DigestSignUpdate(digestContext, message.data(), message.size()))
		throw OpensslException("Couldn't sign message");

	//call finalization with buffer = null to get length of signature
	unsigned int signatureLength = 0;
	if (1 != openssl::EVP_DigestSignFinal(digestContext, NULL, &signatureLength))
		throw OpensslException("Couldn't finalize signature");

	//allocate memory for signature
	unsigned char* tempBuffer = new unsigned char[signatureLength];
	//and get the signature
	if (1 != openssl::EVP_DigestSignFinal(digestContext, tempBuffer, &signatureLength))
		throw OpensslException("Couldn't extract signature");

	//Now init result
	std::vector<unsigned char> result(tempBuffer, tempBuffer + signatureLength);
	return result;
}

bool Crypto::verifySignature(openssl::EVP_PKEY * key, const std::vector<unsigned char>& message, const std::vector<unsigned char>& signature)
{
	openssl::EVP_MD_CTX* digestContext = 0;
	//create and init the context
	if (!(digestContext = openssl::EVP_MD_CTX_create()))
		throw OpensslException("Couldn't create message signing context");
	//Init verification operation
	if (1 != openssl::EVP_DigestVerifyInit(digestContext, NULL, openssl::EVP_sha256(), NULL, key))
		throw OpensslException("Couldn't start the verification process");
	if (1 != openssl::EVP_DigestVerifyUpdate(digestContext, message.data(), message.size()))
		throw OpensslException("Couldn't verify message");

	//verify signature
	size_t size = signature.size();
	if (1 == openssl::EVP_DigestVerifyFinal(digestContext, signature.data(), size))
	{
		return true;
	}
	return false;
}
