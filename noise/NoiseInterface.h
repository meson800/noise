#pragma once

#include "Globals.h"
#include "Fingerprint.h"
#include "Message.h"


namespace RakNet
{
	struct RakNetGUID;
}

namespace NoiseAPI
{
	class NoiseCallbacks;
}

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
	virtual void sendChallenge(const RakNet::RakNetGUID& system, const Fingerprint& fingerprint, bool broadcast = false) = 0;
	//Sends a packet of data to another public key
	//Data is encrypted inside envelope for other public key, then wrapped in a PFS ephemeral key
	virtual void sendData(const Fingerprint& ourFingerprint, const Fingerprint& otherFingerprint, const std::vector<unsigned char>& data) = 0;
	//Gets a verified fingerprint for a given system
	virtual Fingerprint getFingerprint(const RakNet::RakNetGUID& system) = 0;

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

	//Prints out a message
	virtual Message getEncryptedMessage() = 0;

	//--------Helpful Functions---------------------
	//----------------------------------------------
	//Attaches a piece of user data to a fingerprint
	virtual bool setUserData(const Fingerprint& fingerprint, const std::vector<unsigned char>& data) = 0;
	//Retrieves user data from a fingerprint
	virtual std::vector<unsigned char> getUserData(const Fingerprint& fingerprint) = 0;
	//Takes a pointer to a callback class to recieve callback information, returns if it was successful
	virtual bool addCallbackClass(NoiseAPI::NoiseCallbacks * callback) = 0;
	//Removes the callback class, returns if it succeeded
	virtual bool removeCallbackClass(NoiseAPI::NoiseCallbacks * callback) = 0;

	//--------Persistance Functions-----------------
	//----------------------------------------------

	//Saves all keys to keys.db file, with a certain password
	//Returns true if save succeeded, false if it failed
	virtual bool writeKeysToFile(std::vector<unsigned char> password) = 0;
	//Overload, saves with no password
	virtual bool writeKeysToFile() = 0;

	//Loads keys from keys.db file, with a certain password
	//Returns true if loading succeeded, false if it fails
	//Most failures are caused by incorrect password
	virtual bool loadKeysFromFile(std::vector<unsigned char> password) = 0;
	//Overload, loads without password
	virtual bool loadKeysFromFile() = 0;
};
