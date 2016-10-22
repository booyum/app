#pragma once

#include <unistd.h>

#define logMsg(message)  loggerF(message, __FILE__, __LINE__)
#define logErr(message)  loggerF("Error: "message, __FILE__, __LINE__)
#define logWrn(message)  loggerF("Warning: "message, __FILE__, __LINE__)

int initLogFile(const char *logFilePath);
int getTimeStamp(char *buff, size_t buffByteSize);

/* This function is not meant to be called directly, use the macros */ 
void loggerF(const char *message, const char *file, int line);
