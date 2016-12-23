#pragma once

class NoiseInterface;

extern "C" {
	void libnoise_is_present(void);
}

namespace NoiseAPI
{
	NoiseInterface* createNoiseInterface(int portnum);
	NoiseInterface* createNoiseInterface();
	void destroyNoiseInterface(NoiseInterface* inter);
}
