#pragma once
#include <string>
#include <mutex>
#include <map>
#include <NatPunchthroughServer.h>
#include <RakNetTypes.h>
#include <time.h>

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
	//Handles one packet from other nodes, returns true if a packet if we want the interface to handle it
	RakNet::Packet* handlePacket();
	//Sends an arbitrary bitstream
	void sendBitStream(const RakNet::BitStream *stream, const RakNet::AddressOrGUID& system, bool broadcast);
	//Deallocates a packet, needed if we return one out of handlePacket
	void deallocatePacket(RakNet::Packet*);
	//Returns if networking is active
	bool isRunning();

private:
	//Converts return value of Raknet startup into exceptions
	void throwStartupExceptions(const RakNet::StartupResult& result);
	//Converts return value of Raknet connect into exceptions
	void throwConnectionExceptions(const RakNet::ConnectionAttemptResult& result);
	RakNet::RakPeerInterface* ourNode;
	unsigned int port;

	std::map<RakNet::RakNetGUID, bool> nodes;

	RakNet::NatPunchthroughServer natServer;

	time_t lastTime;

	bool started;
	std::mutex mux;

};