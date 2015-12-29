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
#include <openssl/ec.h>
#include <openssl/sha.h>

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

	//set up ephemeral key generation
	if (NULL == (ephemeralParamContext = openssl::EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL)))
		throw OpensslException("Can't create new ephemeral parameter context");
	if (1 != openssl::EVP_PKEY_paramgen_init(ephemeralParamContext))
		throw OpensslException("Can't init ephemeral parameter context");
	if (1 != openssl::EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ephemeralParamContext, NID_X9_62_prime256v1))
		throw OpensslException("Can't set ephemeral parameter curve");
	if (!openssl::EVP_PKEY_paramgen(ephemeralParamContext, &ephemeralKeyParams))
		throw OpensslException("Can't generate ephemeral key generation params");
	if (NULL == (ephemeralKeyContext = openssl::EVP_PKEY_CTX_new(ephemeralKeyParams, NULL)))
		throw OpensslException("Can't generate ephemeral key generation context");
	if (1 != openssl::EVP_PKEY_keygen_init(ephemeralKeyContext))
		throw OpensslException("Can't init ephemeral key generation context");

	Log::writeToLog(Log::INFO, "Done initalizing crypto");
}

Crypto::~Crypto()
{
	//free contexts
	openssl::EVP_PKEY_CTX_free(keyContext);
	openssl::EVP_PKEY_CTX_free(ephemeralParamContext);
	openssl::EVP_PKEY_CTX_free(ephemeralParamContext);
	openssl::EVP_PKEY_free(ephemeralKeyParams);
}

void Crypto::generateKeypair(openssl::EVP_PKEY ** key)
{
	Log::writeToLog(Log::INFO, "Generating RSA keypair");
	if (!keyContext)
		throw KeyGenerationException("Can't generate keypair, no key context");
	if (!openssl::EVP_PKEY_keygen(keyContext, key))
		throw KeyGenerationException("Key generation failed");
}

void Crypto::generateEphemeralKeypair(openssl::EVP_PKEY ** key)
{
	Log::writeToLog(Log::INFO, "Generating ephemeral EC keypair");
	if (!ephemeralKeyContext)
		throw KeyGenerationException("Can't generate ephemeral EC keypair, no context");
	if (!openssl::EVP_PKEY_keygen(ephemeralKeyContext, key))
		throw KeyGenerationException("Ephemeral key generation failed");
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
void Crypto::deriveSharedKey(openssl::EVP_PKEY * key, openssl::EVP_PKEY * otherKey, 
	std::vector<unsigned char>& sharedKeyData, std::vector<unsigned char>& sharedIv)
{
	openssl::EVP_PKEY_CTX* derivationContext = 0;
	//start derivation context
	if (NULL == (derivationContext = openssl::EVP_PKEY_CTX_new(key,NULL)))
		throw OpensslException("Can't create key derivation context");
	if (1 != openssl::EVP_PKEY_derive_init(derivationContext))
		throw OpensslException("Can't init key derivation context");
	//set other key
	if (1 != openssl::EVP_PKEY_derive_set_peer(derivationContext, otherKey))
		throw OpensslException("Can't set other peer key in key derivation");

	//determine shared secret length
	unsigned int secretSize = 0;
	if (1 != openssl::EVP_PKEY_derive(derivationContext, NULL, &secretSize))
		throw OpensslException("Can't derive shared secret");
	//create temp buffer
	unsigned char* tempBuffer = new unsigned char[secretSize];

	if (1 != openssl::EVP_PKEY_derive(derivationContext, tempBuffer, &secretSize))
		throw OpensslException("Can't derive shared secret");

	std::vector<unsigned char> sharedSecret = std::vector<unsigned char>(tempBuffer, tempBuffer + secretSize);
	//deallocate stuff
	EVP_PKEY_CTX_free(derivationContext);
	EVP_PKEY_free(key);
	EVP_PKEY_free(otherKey);

	//Hash the shared secret to derive a secure key
	unsigned char* sharedKey = new unsigned char[SHA512_DIGEST_LENGTH];
	openssl::SHA512(tempBuffer, secretSize, sharedKey);
	sharedKeyData = std::vector<unsigned char>(sharedKey, sharedKey + 32);
	sharedIv = std::vector<unsigned char>(sharedKey + 32, sharedKey + 32 + 16);
	delete[](tempBuffer);
	delete[](sharedKey);
}
