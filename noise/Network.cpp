#include "Network.h"
#include "Globals.h"
#include "Log.h"
#include "Messages.h"

#include <stdlib.h>

#include <RakPeerInterface.h>
#include <RakNetTypes.h>
#include <MessageIdentifiers.h>
#include <BitStream.h>

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
	mux.lock();
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

	//attach to directory server
	Log::writeToLog(Log::INFO, "Connecting to directory server");
	ourNode->AttachPlugin(&natClient);
	ourNode->Connect("titanic.caltech.edu", DIRECTORY_SERVER_PORT, 0, 0);

	Log::writeToLog(Log::L_DEBUG, "Advertising node...");
	mux.unlock();
	broadcastNode();
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

void Network::connectToNode(RakNet::RakNetGUID system)
{
	//check that we aren't connected
	if (ourNode->GetConnectionState(system) == RakNet::ConnectionState::IS_NOT_CONNECTED)
		natClient.OpenNAT(system, natServer);
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
		return (RakNet::Packet*)0;
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
	case ID_UNCONNECTED_PONG:
	{
		Log::writeToLog(Log::INFO, "Got broadcast from system ", packet->guid.ToString());
		std::string address = std::string(packet->systemAddress.ToString());
		address = address.substr(0, address.find_first_of('|'));
		//Try to connect to the system
		mux.lock();
		//check that we aren't connecting to ourselves
		if (packet->guid != ourNode->GetMyGUID())
			ourNode->Connect(address.c_str(), packet->systemAddress.GetPort(), NULL, 0);
		mux.unlock();
		break;
	}
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

	case ID_REQUEST_PUBKEY:
		Log::writeToLog(Log::INFO, "System ", packet->systemAddress.ToString(), " is requesting a public key");
		return packet;
		break;

	case ID_SEND_PUBKEY:
		Log::writeToLog(Log::INFO, "Recieved a publickey from system ", packet->systemAddress.ToString());
		return packet;
		break;

	case ID_SEND_EPHEMERAL_PUBKEY:
		Log::writeToLog(Log::INFO, "Recieved an ephemeral publickey from system ", packet->guid.ToString());
		return packet;
		break;

	case ID_SEND_ENCRYPTED_DATA:
		Log::writeToLog(Log::INFO, "Recieved encrypted data from system ", packet->guid.ToString());
		return packet;
		break;

	case ID_OFFER_NAT_PUNCHTHROUGH:
		Log::writeToLog(Log::INFO, "System ", packet->systemAddress.ToString(), " is offering NAT punchthrough services");
		natServer = packet->systemAddress;
		//request 
		requestNodesFromDirectory();
		break;

	case ID_NODE_LIST:
	{
		Log::writeToLog(Log::INFO, "Directory send us a node list");
		RakNet::BitStream bsIn(packet->data, packet->length, false);
		bsIn.IgnoreBytes(sizeof(RakNet::MessageID));
		RakNet::RakNetGUID newGuid;
		while (bsIn.Read(newGuid))
		{
			connectToNode(newGuid);
		}
		break;
	}

	case ID_NAT_PUNCHTHROUGH_SUCCEEDED:
	{
		Log::writeToLog(Log::INFO, "NAT punchthrough successful");
		connectToNode(packet->systemAddress.ToString(), packet->systemAddress.GetPort());
		break;
	}


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

void Network::broadcastNode()
{
	mux.lock();
	ourNode->Ping("255.255.255.255", SERVER_PORT, false);
	mux.unlock();
}

void Network::requestNodesFromDirectory()
{
	if (ourNode->GetConnectionState(natServer) == RakNet::ConnectionState::IS_CONNECTED)
	{
		Log::writeToLog(Log::INFO, "Requesting nodes from directory");
		RakNet::BitStream bs;
		bs.Write((RakNet::MessageID)ID_REQUEST_NODES);
		ourNode->Send(&bs, MEDIUM_PRIORITY, RELIABLE, 0, natServer, false);
	}
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
