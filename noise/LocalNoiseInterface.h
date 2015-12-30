#pragma once

#include "NoiseInterface.h"
#include "Fingerprint.h"
#include "SymmetricKey.h"
#include <RakNetTypes.h>

class Network;
class Crypto;

#include <mutex>
#include <map>

namespace openssl
{
	struct evp_pkey_st;
	typedef evp_pkey_st EVP_PKEY;
}

class LocalNoiseInterface : public NoiseInterface
{
public:
	LocalNoiseInterface();
	~LocalNoiseInterface();
	//----------Networking functions-----------------
	//-----------------------------------------------

	//Starts the networking dameon
	void startNetworking(int portNumber) override;
	//Stops the networking dameon
	void stopNetworking(void) override;
	//checks if running
	bool isRunning(void) override;
	//Connects to a node
	void connectToNode(const std::string& address, int port = SERVER_PORT) override;
	//Advertises one of our encryption public keys
	void advertiseOurPublicKey(const Fingerprint& fingerprint) override;
	//Sends a challenge to a server with a associated public key to prove the server has the private key
	void sendChallenge(RakNet::RakNetGUID system, const Fingerprint& fingerprint) override;
	//Data is encrypted inside envelope for other public key, then wrapped in a PFS ephemeral key
	void sendData(const Fingerprint& fingerprint, const std::vector<unsigned char>& data) override;

	//---------Cryptography Functions----------------
	//-----------------------------------------------

	//generates new non-ephemeral encryption key, returns fingerprint for key
	Fingerprint generateNewEncryptionKey() override;
	//Returns the number of non-ephemeral keypairs we have
	unsigned int numEncryptionKeys() override;

private:
	//Handles a single packet in the queue
	void handlePacket(void);
	//Requests a publickey from a remote system
	void requestPublickey(const Fingerprint& fingerprint, RakNet::RakNetGUID system);
	//Sends a publickey if we have it
	void sendPublickey(const Fingerprint& fingerprint, RakNet::RakNetGUID system);
	//Signs a challenge if we can
	void verifyChallenge(const Fingerprint& fingerprint, const std::vector<unsigned char>& challenge, RakNet::RakNetGUID system);

	//Sends ephemeral public key to other system to derive PFS key so we can send our data along
	void sendEphemeralPublicKey(const Fingerprint& fingerprint);
	void sendEphemeralPublicKey(RakNet::RakNetGUID system);
	//Sends encrypted data using double encryption
	void sendEncryptedData(const Fingerprint& fingerprint);

	std::mutex mux;

	Network* network;
	Crypto* crypto;

	std::map<Fingerprint, openssl::EVP_PKEY*> ourEncryptionKeys;
	std::map<Fingerprint, openssl::EVP_PKEY*> otherEncryptionKeys;
	std::map<Fingerprint, RakNet::RakNetGUID> verifiedSystems;
	std::map<Fingerprint, std::vector<unsigned char>> liveChallenges;

	std::map<Fingerprint, std::vector<unsigned char>> outgoingData;
	std::map<RakNet::RakNetGUID, openssl::EVP_PKEY*> ourEphemeralKeys;
	std::map<RakNet::RakNetGUID, openssl::EVP_PKEY*> otherEphemeralKeys;
	std::map<RakNet::RakNetGUID, SymmetricKey> sharedKeys;

	std::map<RakNet::RakNetGUID, std::vector<Fingerprint>> nodes;
};