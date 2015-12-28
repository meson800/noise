#include "Network.h"
#include "Globals.h"
#include "Log.h"
#include "Messages.h"

#include <RakPeerInterface.h>
#include <RakNetTypes.h>
#include <MessageIdentifiers.h>

Network::Network(unsigned int listenPort) : port(listenPort), started(false)
{
	Log::writeToLog(Log::INFO, "Listening port set to ", port, "\n");
	mux.lock();
	ourNode = RakNet::RakPeerInterface::GetInstance();
	mux.unlock();
}

Network::Network() : port(SERVER_PORT), started(false)
{
	Log::writeToLog(Log::L_DEBUG, "No listening port provided, using default port");
	mux.lock();
	ourNode = RakNet::RakPeerInterface::GetInstance();
	mux.unlock();
}

void Network::startNode()
{
	if (started)
	{
		throw NetworkStartupException("Networking already started");
	}
	Log::writeToLog(Log::INFO, "Starting networking...");
	Log::writeToLog(Log::L_DEBUG, "Networking will be started with ", MAX_CONNECTIONS, " maxiumum connections...");
	ourNode->SetMaximumIncomingConnections(MAX_CONNECTIONS);
	RakNet::SocketDescriptor sd(port, 0);

	try
	{
		throwStartupExceptions(ourNode->Startup(MAX_CONNECTIONS, &sd, 1));
		Log::writeToLog(Log::INFO, "Network startup done");
		started = true;
	}
	catch (NetworkStartupException const &e)
	{
		Log::writeToLog(Log::FATAL, "Couldn't start networking. Startup error:", e.what());
	}
}

void Network::shutdownNode()
{
	Log::writeToLog(Log::INFO, "Shutting down networking...");
	mux.lock();
	ourNode->Shutdown(10 * 1000);
	RakNet::RakPeerInterface::DestroyInstance(ourNode);
	started = false;
	mux.unlock();
}

void Network::connectToNode(std::string const &address)
{
	connectToNode(address, SERVER_PORT);
}

void Network::connectToNode(std::string const &address, unsigned int port)
{
	try
	{
		mux.lock();
		throwConnectionExceptions(ourNode->Connect(address.c_str(), port, 0, 0));
		mux.unlock();
	}
	catch (NetworkConnectionException const &e)
	{
		Log::writeToLog(Log::ERR, "Couldn't connect to node. Error:", e.what());
		mux.unlock();
	}
}

RakNet::Packet* Network::handlePacket()
{
	mux.lock();
	if (!started)
	{
		mux.unlock();
		return false;
	}
	RakNet::Packet* packet = ourNode->Receive();
	mux.unlock();
	if (packet == 0)
	{
		//no more packets to handle
		return 0;
	}

	//now handle the packets
	switch (packet->data[0])
	{
	case ID_REMOTE_DISCONNECTION_NOTIFICATION:
		Log::writeToLog(Log::INFO, "System ", packet->guid.ToString(), " has disconnected");
		return packet;
		break;

	case ID_REMOTE_CONNECTION_LOST:
		Log::writeToLog(Log::INFO, "System ", packet->guid.ToString(), " has lost the connection");
		return packet;
		break;

	case ID_REMOTE_NEW_INCOMING_CONNECTION:
		Log::writeToLog(Log::INFO, "System ", packet->systemAddress.ToString(), " has connected");
		return packet;
		break;

	case ID_CONNECTION_REQUEST_ACCEPTED:
		Log::writeToLog(Log::INFO, "Successfully connected to system ", packet->guid.ToString());
		return packet;
		break;

	case ID_NEW_INCOMING_CONNECTION:
		Log::writeToLog(Log::INFO, "System ", packet->systemAddress.ToString(), " is trying to connect");
		return packet;
		break;

	case ID_NO_FREE_INCOMING_CONNECTIONS:
		Log::writeToLog(Log::INFO, "Couldn't connect to system ", packet->systemAddress.ToString(), ", too many nodes connected");
		break;

	case ID_DISCONNECTION_NOTIFICATION:
		Log::writeToLog(Log::INFO, "Disconnected from system ", packet->guid.ToString());
		return packet;
		break;

	case ID_CONNECTION_LOST:
		Log::writeToLog(Log::INFO, "Connection lost from system ", packet ->guid.ToString());
		return packet;
		break;

	case ID_OFFER_PUBKEY:
		Log::writeToLog(Log::INFO, "System ", packet->systemAddress.ToString(), " is advertising a public key");
		return packet;
		break;

	default:
		Log::writeToLog(Log::L_DEBUG, "Got packet with identifier ", packet->data[0]);
		return packet;
		break;
	}
	ourNode->DeallocatePacket(packet);
	return 0;
}

void Network::sendBitStream(const RakNet::BitStream * stream, const RakNet::AddressOrGUID & system, bool broadcast)
{
	mux.lock();
	ourNode->Send(stream, MEDIUM_PRIORITY, RELIABLE, 0, system, broadcast);
	mux.unlock();
}

void Network::deallocatePacket(RakNet::Packet* packet)
{
	ourNode->DeallocatePacket(packet);
}

bool Network::isRunning()
{
	mux.lock();
	bool result = started;
	mux.unlock();
	return result;
}

void Network::throwStartupExceptions(const RakNet::StartupResult & result)
{
	switch (result)
	{
	case RakNet::StartupResult::RAKNET_STARTED:
		//good, no exception
		break;

	case RakNet::StartupResult::COULD_NOT_GENERATE_GUID:
		throw NetworkStartupException("Could not generate network GUID");
		break;

	case RakNet::StartupResult::FAILED_TO_CREATE_NETWORK_THREAD:
		throw NetworkStartupException("Failed to create networking thread");
		break;

	case RakNet::StartupResult::INVALID_MAX_CONNECTIONS:
		throw NetworkStartupException("Invalid maximum connections");
		break;

	case RakNet::StartupResult::INVALID_SOCKET_DESCRIPTORS:
		throw NetworkStartupException("Invalid socket descriptor (check selected port)");
		break;

	case RakNet::StartupResult::PORT_CANNOT_BE_ZERO:
		throw NetworkStartupException("Port cannot be zero");
		break;

	case RakNet::StartupResult::RAKNET_ALREADY_STARTED:
		throw NetworkStartupException("Raknet has already been started");
		break;

	case RakNet::StartupResult::SOCKET_FAILED_TEST_SEND:
		throw NetworkStartupException("Socket failed test send");
		break;

	case RakNet::StartupResult::SOCKET_FAILED_TO_BIND:
		throw NetworkStartupException("Socket failed to bind");
		break;

	case RakNet::StartupResult::SOCKET_FAMILY_NOT_SUPPORTED:
		throw NetworkStartupException("Socket family not supported");
		break;

	case RakNet::StartupResult::SOCKET_PORT_ALREADY_IN_USE:
		throw NetworkStartupException("Socket port already in use");
		break;

	case RakNet::StartupResult::STARTUP_OTHER_FAILURE:
		throw NetworkStartupException("Unknown startup failure");
		break;

	default:
		throw NetworkStartupException("Unknown error");
		break;
	}
}

void Network::throwConnectionExceptions(RakNet::ConnectionAttemptResult const &result)
{
	switch (result)
	{
	case RakNet::ConnectionAttemptResult::CONNECTION_ATTEMPT_STARTED:
		//good, no error
		break;

	case RakNet::ConnectionAttemptResult::ALREADY_CONNECTED_TO_ENDPOINT:
		throw NetworkConnectionException("Already connected to this node");
		break;

	case RakNet::ConnectionAttemptResult::CANNOT_RESOLVE_DOMAIN_NAME:
		throw NetworkConnectionException("Cannot resolve domain name");
		break;

	case RakNet::ConnectionAttemptResult::CONNECTION_ATTEMPT_ALREADY_IN_PROGRESS:
		throw NetworkConnectionException("A connection attempt is already in progress");
		break;

	case RakNet::ConnectionAttemptResult::INVALID_PARAMETER:
		throw NetworkConnectionException("Invalid connection parameter");
		break;

	case RakNet::ConnectionAttemptResult::SECURITY_INITIALIZATION_FAILED:
		throw NetworkConnectionException("Security initalization failed");
		break;

	default:
		throw NetworkConnectionException("Unknown connection error");
		break;
	}
}
