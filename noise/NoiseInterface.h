#pragma once

#include "Globals.h"

//forward definitions
namespace std
{
	class string;
}

class NoiseInterface
{
public:
	//----------Networking functions-----------------
	//-----------------------------------------------

	//Starts the networking dameon
	virtual void startNetworking(int portNumber) = 0;
	//Stops the networking dameon
	virtual void stopNetworking(void) = 0;
	//Connects to a node
	virtual void connectToNode(const std::string& address, int port = SERVER_PORT) = 0;

	//---------Cryptography Functions----------------
	//-----------------------------------------------

	//generates encryption key, returns fingerprint for key
	virtual unsigned int generateNewEncKey() = 0;
	//
};