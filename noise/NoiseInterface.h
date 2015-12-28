#pragma once

#include "Globals.h"
#include "Fingerprint.h"



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
	//Handles a single packet in the queue
	virtual void handlePacket(void) = 0;
	//Connects to a node
	virtual void connectToNode(const std::string& address, int port = SERVER_PORT) = 0;

	//---------Cryptography Functions----------------
	//-----------------------------------------------

	//generates new non-ephemeral encryption key, returns fingerprint for key
	virtual Fingerprint generateNewEncryptionKey() = 0;
	//Returns the number of non-ephemeral keypairs we have
	virtual unsigned int numEncryptionKeys() = 0;
};