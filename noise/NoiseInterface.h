#pragma once

#include "Globals.h"
#include "Fingerprint.h"
#include <RakNetTypes.h>

class NoiseInterface
{
public:
	//----------Networking functions-----------------
	//-----------------------------------------------

	//Starts the networking dameon, this function never returns
	virtual void startNetworking(int portNumber) = 0;
	//Stops the networking dameon
	virtual void stopNetworking(void) = 0;
	//checks if running
	virtual bool isRunning(void) = 0;
	//Connects to a node
	virtual void connectToNode(const std::string& address, int port = SERVER_PORT) = 0;
	//Advertises one of our encryption public keys
	virtual void advertiseOurPublicKey(const Fingerprint& fingerprint) = 0;
	//Sends a challenge to a server with a associated public key to prove the server has the private key
	virtual void sendChallenge(RakNet::RakNetGUID system, const Fingerprint& fingerprint) = 0;
	//Sends a packet of data to another public key
	//Data is encrypted inside envelope for other public key, then wrapped in a PFS ephemeral key
	virtual void sendData(const Fingerprint& fingerprint, const std::vector<unsigned char>& data) = 0;
	//Gets a verified fingerprint for a given system
	virtual Fingerprint getFingerprint(RakNet::RakNetGUID system) = 0;

	//---------Cryptography Functions----------------
	//-----------------------------------------------

	//generates new non-ephemeral encryption key, returns fingerprint for key
	virtual Fingerprint generateNewEncryptionKey() = 0;
	//Returns the number of non-ephemeral keypairs we have
	virtual unsigned int numOurEncryptionKeys() = 0;
	//Gets one of our encryption keys by index
	virtual Fingerprint getOurEncryptionKeyByIndex(unsigned int index)  = 0;
	//Returns the number of other encryption keys
	virtual unsigned int numOtherEncryptionKeys() = 0;
	//Gets one of the other encryption keys by index
	virtual Fingerprint getOtherEncryptionKeyByIndex(unsigned int index) = 0;

	//Checks if other encryption key belongs to a verified computer
	virtual bool hasVerifiedNode(const Fingerprint& fingerprint) = 0;
};