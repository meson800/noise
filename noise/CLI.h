#pragma once

#include <mutex>

//forward definitions
class NoiseInterface;

class CLI
{
public:
	//Initalize with interface to Noise client
	CLI(NoiseInterface* _interface);
	//Run interface (usually inside seperate thread)
	void runInterface();
	//Stops the interface (from external, main thread)
	void stopInterface();

private:
	bool shouldStop;
	NoiseInterface* interface;
	std::mutex mut;
};