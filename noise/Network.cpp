#include "Network.h"
#include "Globals.h"
#include "Log.h"

#include <RakPeerInterface.h>

Network::Network(unsigned int listenPort) : port(listenPort)
{
	Log::writeToLog(Log::INFO, "Listening port set to ", port, "\n");
}

Network::Network() : port(50000)
{
	Log::writeToLog(Log::L_DEBUG, "No listening port provided, using default port");
	ourNode = RakNet::RakPeerInterface::GetInstance();
}

void Network::startNode()
{
	Log::writeToLog(Log::INFO, "Starting networking...");
	Log::writeToLog(Log::L_DEBUG, "Networking will be started with ", MAX_CONNECTIONS, " maxiumum connections...");
	RakNet::SocketDescriptor sd(port, 0);

	try
	{
		throwStartupExceptions(ourNode->Startup(MAX_CONNECTIONS, &sd, 1));
		Log::writeToLog(Log::INFO, "Network startup done");
	}
	catch (NetworkStartupException const &e)
	{
		Log::writeToLog(Log::ERR, "Couldn't start networking. Startup error:", e.what());
	}
}

void Network::connectToNode(std::string address, unsigned int port)
{
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
