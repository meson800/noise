#pragma once

#include "NoiseInterface.h"
#include "Fingerprint.h"
#include "SymmetricKey.h"
#include <RakNetTypes.h>
#include <time.h>

class Network;
class Crypto;

#include <mutex>
#include <map>

namespace openssl
{
	struct evp_pkey_st;
	typedef evp_pkey_st EVP_PKEY;
}

namespace NoiseAPI
{
	class NoiseCallbacks;
}

struct DataRequest
{
	Fingerprint ourKey;
	Fingerprint otherKey;
	openssl::EVP_PKEY* ourEphemeralKey;
	openssl::EVP_PKEY* otherEphemeralKey;
	SymmetricKey sharedKey;
	RakNet::RakNetGUID otherSystem;
	std::vector<unsigned char> data;

};
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
	void sendChallenge(const RakNet::RakNetGUID& system, const Fingerprint& fingerprint, bool broadcast = false) override;
	//Data is encrypted inside envelope for other public key, then wrapped in a PFS ephemeral key
	void sendData(const Fingerprint& ourFingerprint, const Fingerprint& otherFingerprint, const std::vector<unsigned char>& data) override;
	//Gets a verified fingerprint for a given system
	Fingerprint getFingerprint(const RakNet::RakNetGUID& system);

	//---------Cryptography Functions----------------
	//-----------------------------------------------

	//generates new non-ephemeral encryption key, returns fingerprint for key
	Fingerprint generateNewEncryptionKey() override;
	//Returns the number of non-ephemeral keypairs we have
	unsigned int numOurEncryptionKeys() override;
	//Gets one of our encryption keys by index
	Fingerprint getOurEncryptionKeyByIndex(unsigned int index) override;
	//Returns the number of other encryption keys
	unsigned int numOtherEncryptionKeys() override;
	//Gets one of the other encryption keys by index
	Fingerprint getOtherEncryptionKeyByIndex(unsigned int index) override;

	//Checks if other encryption key belongs to a verified computer
	bool hasVerifiedNode(const Fingerprint& fingerprint) override;

	//Gets a message
	Message getEncryptedMessage() override;

	//--------Helpful Functions---------------------
	//----------------------------------------------
	//Attaches a piece of user data to a fingerprint
	bool setUserData(const Fingerprint& fingerprint, const std::vector<unsigned char>& data) override;
	//Retrieves user data from a fingerprint
	std::vector<unsigned char> getUserData(const Fingerprint& fingerprint) override;

	//--------Persistance Functions-----------------
	//----------------------------------------------

	//Saves all keys to keys.db file, with a certain password
	//Returns true if save succeeded, false if it failed
	bool writeKeysToFile(std::vector<unsigned char> password) override;
	//Overload, saves with no password
	bool writeKeysToFile() override;

	//Loads keys from keys.db file, with a certain password
	//Returns true if loading succeeded, false if it fails
	//Most failures are caused by incorrect password
	bool loadKeysFromFile(std::vector<unsigned char> password) override;
	//Overload, loads without password
	bool loadKeysFromFile() override;

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

	//Extracts all keys to bytes
	std::vector<unsigned char> keysToBytes();
	//Turns bytes extracted into keys
	//Returns true on success
	bool bytesToKeys(const std::vector<unsigned char>& bytes);

	//last time
	time_t lastAdvertiseTime;

	std::mutex mux;

	Network* network;
	Crypto* crypto;

	std::vector<Message> incomingMessages;

	std::vector<Fingerprint> ourFingerprints;
	std::vector<Fingerprint> otherFingerprints;
	std::map<Fingerprint, openssl::EVP_PKEY*> ourEncryptionKeys;
	std::map<Fingerprint, openssl::EVP_PKEY*> otherEncryptionKeys;
	std::map<Fingerprint, RakNet::RakNetGUID> verifiedSystems;
	std::map<Fingerprint, std::vector<unsigned char>> liveChallenges;

	std::map<RakNet::RakNetGUID,DataRequest> outgoingData;

	std::map<RakNet::RakNetGUID, std::vector<Fingerprint>> nodes;

	std::map<Fingerprint, std::vector<unsigned char>> userdata;
};
