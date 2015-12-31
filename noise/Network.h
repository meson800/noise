#pragma once
#include <string>
#include <mutex>

//forward definitions
namespace RakNet
{
	class RakPeerInterface;
	enum StartupResult;
	enum ConnectionAttemptResult;
	struct Packet;
	class BitStream;
	struct AddressOrGUID;
}

class Network
{
public:
	//initalize network with port number, doesn't actually start networking
	Network(unsigned int listenPort);
	//initalize network with default port
	Network();
	//actually start networking
	void startNode();
	//stops networking
	void shutdownNode();
	//explicitly connect to node
	void connectToNode(std::string const &address, unsigned int port);
	//explicitly connect to node using default port
	void connectToNode(std::string const &address);
	//Handles one packet from other nodes, returns true if a packet if we want the interface to handle it
	RakNet::Packet* handlePacket();
	//Sends an arbitrary bitstream
	void sendBitStream(const RakNet::BitStream *stream, const RakNet::AddressOrGUID& system, bool broadcast);
	//Deallocates a packet, needed if we return one out of handlePacket
	void deallocatePacket(RakNet::Packet*);
	//Returns if networking is active
	bool isRunning();
	//Broadcasts our server over LAN
	void broadcastNode();

private:
	//Converts return value of Raknet startup into exceptions
	void throwStartupExceptions(const RakNet::StartupResult& result);
	//Converts return value of Raknet connect into exceptions
	void throwConnectionExceptions(const RakNet::ConnectionAttemptResult& result);
	RakNet::RakPeerInterface* ourNode;
	unsigned int port;

	bool started;
	std::mutex mux;

};