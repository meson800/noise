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
	//checks if interface is still running
	bool isRunning();
	//Stops the interface (from external, main thread)
	void stopInterface();

private:
	//selection functions
	//These block until the user selects a key to send to/use
	unsigned int selectOurKey();
	unsigned int selectOtherKey();

	bool shouldStop;
	bool running;
	NoiseInterface* inter;
	std::mutex mut;
};