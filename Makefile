CC = g++
CFLAGS = -std=c++11 -g -fpermissive -I../RakNet/Source -pthread
CLIBS = -l crypto -l ssl
LIB = noise
LIB_PATH = -L /usr/lib/x86_64-linux-gnu/libfakeroot -L /usr/lib/i386-linux-gnu/mesa -L /lib/i386-linux-gnu -L /usr/lib/i386-linux-gnu -L /usr/local/lib -L /lib/x86_64-linux-gnu -L /usr/lib/x86_64-linux-gnu -L /usr/lib/x86_64-linux-gnu/mesa-egl -L /usr/lib/x86_64-linux-gnu/mesa -L /lib -L /usr/lib
PROG_cli = noise_cli
PROG_server = noise_directory_server
PROG_lib = libnoise
OBJS = noise/NoiseAPI.o noise/LocalNoiseInterface.o noise/Network.o noise/Message.o noise/Helpers.o noise/Fingerprint.o noise/CryptoHelpers.o noise/Crypto.o noise/Envelope.o noise/SymmetricKey.o noise/Log.o
SRCS = noise/NoiseAPI.cpp noise/LocalNoiseInterface.cpp noise/Network.cpp noise/Message.cpp  noise/Helpers.cpp noise/Fingerprint.cpp noise/CryptoHelpers.cpp noise/Crypto.cpp noise/Envelope.cpp noise/SymmetricKey.cpp noise/Log.cpp
LIB_HEADERS_TO_COPY = noise/NoiseInterface.h noise/NoiseAPI.h noise/Globals.h noise/Fingerprint.h noise/Message.h noise/Helpers.h noise/Exceptions.h noise/Log.h


CLI_OBJS = CommandLineReferenceImplementation/CLI.o CommandLineReferenceImplementation/main.o
CLI_SRCS = CommandLineReferenceImplementation/CLI.cpp CommandLineReferenceImplementations/main.cpp
CLI_LIBS = -l noise -ldl
CLI_LIB_PATH = lib
CLI_INCLUDE_PATH = include

SERVER_OBJS = NatPunchthroughServer/main.o NatPunchthroughServer/Network.o
SERVER_SRCS = NatPunchthroughServer/main.cpp NatPunchthroughServer/Network.cpp

RAKNET_SRCS = $(wildcard ../RakNet/Source/*.cpp)
RAKNET_OBJS = $(patsubst %.cpp, %.o, $(RAKNET_SRCS))

all: rakNet noise directoryServer cli

clean:
	$(RM) -R count *.o
	$(RM) -R count noise/*.o
	$(RM) -R count CommandLineReferenceImplementation/*.o
	$(RM) -R count NatPunchthroughServer/*.o
	$(RM) -R count ../RakNet/Source/*.o
	$(RM) -R count lib/*
	$(RM) -R count include/*
	$(RM) -R count $(PROG_server)
	$(RM) -R count $(PROG_cli)

noise: $(OBJS) checkDirs $(LIB_HEADERS_TO_COPY)
	ld -Ur $(LIB_PATH) -o noise/noise.o $(OBJS) $(RAKNET_OBJS) $(CLIBS)
	ar rcs lib/libnoise.a noise/noise.o
	cp $(LIB_HEADERS_TO_COPY) include

checkDirs:
	@if [ -d "lib" ]; then echo "Lib directory found"; else mkdir lib; echo "Lib directory created"; fi;
	@if [ -d "include" ]; then echo "Include directory found"; else mkdir include; echo "Include directory created"; fi;

cli: $(CLI_OBJS)
	$(CC) $(CFLAGS) -L $(CLI_LIB_PATH) -o $(PROG_cli) $(CLI_OBJS) $(CLI_LIBS) 

directoryServer: $(SERVER_OBJS) $(RAKNET_OBJS) noise/Log.o
	$(CC) $(CFLAGS) -o $(PROG_server) $(SERVER_OBJS) $(RAKNET_OBJS) noise/Log.o $(CLIBS) -l pthread

rakNet: rakNetDownload $(RAKNET_OBJS)

rakNetDownload:
	@echo "Checking for existance of RakNet folder..."
	@if [ -d "../RakNet" ]; then echo "RakNet correctly downloaded"; else echo "RakNet not downloaded, cloning from Github..."; git clone https://github.com/OculusVR/RakNet.git ../RakNet; fi

CommandLineReferenceImplementation/%.o: CommandLineReferenceImplementation/%.cpp
	$(CC) $(CFLAGS) -L $(CLI_LIB_PATH) -I $(CLI_INCLUDE_PATH) -c -o $(patsubst %.cpp, %.o, $<) $< 

%.o:  %.cpp
	$(CC) $(CFLAGS) -c -o $(patsubst %.cpp, %.o, $<) $< $(CLIBS)

depend:
	makedepend -- $(CFLAGS) -- $(SRCS)
