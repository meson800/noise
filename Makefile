CC = g++
CFLAGS = -g -Wall
PROG = noise
PROG_server = noise_directory_server
OBJS = noise/LocalNoiseInterface.o noise/Network.o noise/CLI.o noise/Message.o noise/main.o noise/Helpers.o noise/Fingerprint.o noise/CryptoHelpers.o noise/Crypto.o noise/Envelope.o noise/SymmetricKey.o noise/Log.o
SRCS = noise/LocalNoiseInterface.cpp noise/Network.cpp noise/CLI.cpp noise/Message.cpp noise/main.cpp noise/Helpers.cpp noise/Fingerprint.cpp noise/CryptoHelpers.cpp noise/Crypto.cpp noise/Envelope.cpp noise/SymmetricKey.cpp noise/Log.cpp

SERVER_OBJS = NatPunchthroughServer/main.o NatPunchthroughServer/Network.o
SERVER_SRCS = NatPunchthroughServer/main.cpp NatPunchthroughServer/Network.cpp

all: noise directoryServer

clean:
	$(RM) -R count *.o

noise: $(OBJS)
	$(CC) $(CFLAGS) -o $(PROG) $(OBJS)

directoryServer: $(SERVER_OBJS)
	$(CC) $(CFLAGS) -o $(PROG_server) $(SERVER_OBJS)
.cpp.o:
	$(CC) $(CFLAGS) -c $*.cpp

depend:
	makedepend -- $(CFLAGS) -- $(SRCS)
