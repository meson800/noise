#pragma once

class NoiseInterface;

namespace NoiseAPI
{
	NoiseInterface* createNoiseInterface(int portnum);
	NoiseInterface* createNoiseInterface();
	void destroyNoiseInterface(NoiseInterface* inter);
}