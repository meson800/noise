#pragma once
#include <string>

//forward definitions
namespace RakNet
{
	class RakPeerInterface;
	enum StartupResult;
}

class Network
{
public:
	Network(unsigned int listenPort);
	Network();
	void startNode();
	void shutdownNode();
	void connectToNode(std::string address, unsigned int port);

private:
	void throwStartupExceptions(const RakNet::StartupResult& result);
	RakNet::RakPeerInterface* ourNode;
	unsigned int port;

	bool started;

};