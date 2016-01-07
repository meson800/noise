CC = g++
CFLAGS = -std=c++11 -g -fpermissive -I../RakNet/Source -I~/temp_bin/include -L~/temp_bin/lib -l crypto -l ssl -l pthread
PROG = noise_client
PROG_server = noise_directory_server
OBJS = noise/LocalNoiseInterface.o noise/Network.o noise/CLI.o noise/Message.o noise/main.o noise/Helpers.o noise/Fingerprint.o noise/CryptoHelpers.o noise/Crypto.o noise/Envelope.o noise/SymmetricKey.o noise/Log.o
SRCS = noise/LocalNoiseInterface.cpp noise/Network.cpp noise/CLI.cpp noise/Message.cpp noise/main.cpp noise/Helpers.cpp noise/Fingerprint.cpp noise/CryptoHelpers.cpp noise/Crypto.cpp noise/Envelope.cpp noise/SymmetricKey.cpp noise/Log.cpp

SERVER_OBJS = NatPunchthroughServer/main.o NatPunchthroughServer/Network.o
SERVER_SRCS = NatPunchthroughServer/main.cpp NatPunchthroughServer/Network.cpp

RAKNET_SRCS = $(wildcard ../RakNet/Source/*.cpp)
RAKNET_OBJS = $(patsubst %.cpp, %.o, $(RAKNET_SRCS))

all: rakNet noise directoryServer

clean:
	$(RM) -R count *.o

noise: $(OBJS)
	$(CC) $(CFLAGS) -o $(PROG) $(OBJS) $(RAKNET_OBJS)

directoryServer: $(SERVER_OBJS) $(RAKNET_OBJS) noise/Log.o
	$(CC) $(CFLAGS) -o $(PROG_server) $(SERVER_OBJS) $(RAKNET_OBJS) noise/Log.o

rakNet: $(RAKNET_OBJS)

%.o:  %.cpp
	$(CC) $(CFLAGS) -c -o $(patsubst %.cpp, %.o, $<) $<

depend:
	makedepend -- $(CFLAGS) -- $(SRCS)
