#pragma once
#include <cstdint>

class Message;
class Fingerprint;

namespace NoiseAPI
{
	class NoiseCallbacks
	{
	public:
		virtual void MessageRecieved(const Message& message);
		virtual void NodeConnected(uint64_t node_id);
		virtual void NodeDisconnected(uint64_t node_id);
		virtual void FingerprintVerified(uint64_t node_id, const Fingerprint& fingerprint);
	};
}
