#include "Log.h"

std::mutex Log::writeMutex;
std::string Log::logFilename;
bool Log::writeToConsole;

Log::LogLevel Log::logLevel = Log::LogLevel::WARN;
const char *  Log::levelStrings[] = { "[ALL]", "[DEBUG]", "[INFO]", "[WARN]", "[ERROR]", "[FATAL]", "[OFF]" };

void Log::setLogfile(const std::string & newLogFilename)
{
	logFilename = newLogFilename;
}

void Log::shouldMirrorToConsole(bool newValue)
{
	writeToConsole = newValue;
}

void Log::clearLog()
{
    std::ofstream logFile = std::ofstream(logFilename, std::ios::out);
    logFile.close();
}

void Log::setLogLevel(LogLevel level)
{
    Log::writeToLog("Changing log level to ", levelStrings[level],"\n");
    logLevel = level;
}

bool Log::shouldLog(LogLevel level)
{
    return level >= logLevel;
}

void Log::writeToLogThreadUnsafe()
{
    std::ofstream logFile = std::ofstream(logFilename, std::ios::app);
    logFile << "\n";
    logFile.close();
	if (writeToConsole)
	{
		std::cout << "\n";
	}
}
