#pragma once

#include <mutex>
#include <string>
#include <iostream>
#include <fstream>

#include "Exceptions.h"

class Log
{
public:
    //L_DEBUG because windows global defines DEBUG :(
    enum LogLevel {ALL,L_DEBUG,INFO,WARN,ERR,FATAL,OFF};
	static void setLogfile(const std::string& newLogFilename);
	static void shouldMirrorToConsole(bool newValue);
    static void clearLog();
    static void setLogLevel(LogLevel level);
	
    //thread safe definition, to avoid recursive mutex
    template<typename ... Types>
    static void writeToLog(Types ... rest)
    {
		if (logFilename.size() == 0)
		{
			throw LoggingException("Tried to log without setting log filename");
		}
        writeMutex.lock();
        writeToLogThreadUnsafe(rest...);
        writeMutex.unlock();
    }

    //varadic write to log so its easier to use
    template<typename ... Types>
    //case that returns if messageLevel isn't enough to log
    static void writeToLogThreadUnsafe(LogLevel messageLevel, Types ... rest)
    {
        if (shouldLog(messageLevel))
        {
            std::ofstream logFile;
            logFile.open(logFilename, std::ios::app);
            logFile << levelStrings[messageLevel];
            logFile.close();
			if (writeToConsole)
			{
				std::cout << levelStrings[messageLevel];
			}
            writeToLogThreadUnsafe(rest...);
        }
    }

    template<typename T, typename ... Types>
    //Generic case, prints out using << operator
    static void writeToLogThreadUnsafe(T first, Types ... rest)
    {
        std::ofstream logFile;
        logFile.open(logFilename, std::ios::app);
        logFile << first;
        logFile.close();
		if (writeToConsole)
		{
			std::cout << first;
		}
        //recurse for other arguments
        writeToLogThreadUnsafe(rest...);
    }
    //base case, write out newline
    static void writeToLogThreadUnsafe();

private:
	static bool writeToConsole;
    static std::mutex writeMutex;
	static std::string logFilename;
    static const char* levelStrings[];
    static bool shouldLog(LogLevel level);
    static LogLevel logLevel;
};
