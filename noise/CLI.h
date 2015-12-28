#pragma once

#include <mutex>

//forward definitions
class Network;
class Crypto;

class CLI
{
public:
	//Initalize with a network interface
	CLI(Network* _network, Crypto* _crypto);
	//Run interface (usually inside seperate thread)
	void runInterface();
	//Stops the interface (from external, main thread)
	void stopInterface();

private:
	bool shouldStop;
	Network* network;
	Crypto* crypto;
	std::mutex mut;
};