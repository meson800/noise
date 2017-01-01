#include "NoiseCallbacks.h"

namespace NoiseAPI
{
	void NoiseCallbacks::MessageRecieved(const Message& message) {}
	void NoiseCallbacks::NodeConnected(uint64_t node_id) {}
	void NoiseCallbacks::NodeDisconnected(uint64_t node_id) {}
	void NoiseCallbacks::FingerprintVerified(uint64_t node_id, const Fingerprint& fingerprint) {}
}
