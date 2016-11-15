#include <noise/NoiseAPI.h>

//Tries to use the NoiseAPI to create and destroy an interface
int main() {
	NoiseInterface * inter = NoiseAPI::createNoiseInterface();
	NoiseAPI::destroyNoiseInterface(inter);
	return 0;
}
