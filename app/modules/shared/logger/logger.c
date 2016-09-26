#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/file.h>

#include "logger.h"

static FILE *gLogFile;
static int  gLogFileFd;


/* initLogger initializes the logging functions such that the macros logMsg,
 * logErr, logWrn, etc, can be utilized. It is passed the full path to the 
 * file to output the logs to. The logging functionality is implemented as 
 * a singleton object, however it is thread safe thanks to flock. Note that
 * reinitialization is not supported, so changing the log file path after 
 * initialization cannot be done.
 *
 * Returns 0 on error, 1 on success. 
 */
int initLogFile(char *logFilePath)
{
  /* Basic error checking */
  if(logFilePath == NULL){
    printf("logFilePath was NULL, logging will fail\n");
    return 0;
  }
     
  /* Reinitialization is not supported */
  if(gLogFile != NULL){
    printf("Log file reinitialization unsupported\n");
    return 0;
  }

  /* Open the file at logFilePath for appending, created if doesn't exist */
  gLogFile = fopen(logFilePath, "a");
  if(gLogFile == NULL){
    printf("Failed to open logfile\n"); 
    return 0;
  }
  
  /* Get the file descriptor, this is used for some functions in loggerF */ 
  gLogFileFd = fileno(gLogFile);
  if( gLogFileFd == -1 ){
    printf("Failed to get logfile FD, logging will fail\n");
    return 0;
  }
  
  return 1; 
}

/* loggerF is the general purpose logging function, though it is not meant to be
 * called directly, but rather with the macros defined in the logger.h file. 
 * loggerF printfs message (as well as macro defined indicators, the file from 
 * which it was called, the line in the file where it was called, and a 
 * timestamp) to the terminal. In the case that initLogfile has been called, 
 * the previously described string will also be appended to the initialized log 
 * file.
 * 
 * This function has no return value, though it can silently fail. 
 */  
void loggerF(char *message, char *file, int line)
{ 
  size_t maxTimeStampBytesize = 200;
  char timestamp[maxTimeStampBytesize];
   
  /* Get the current timestamp, if this fails ensure timestamp array is NULL 
   * terminated */ 
  if( !getTimeStamp(timestamp, maxTimeStampBytesize) ){
    printf("Error: Failed to get timestamp for log file\n"); 
    timestamp[0] = '\0'; 
  }
  
  /* Output the log message to the terminal */  
  printf("%s in %s : %i at %s\n", message, file, line, timestamp); 
  
  /* If initLogFile has not been called then we are done logging. There is 
   * no need to NULL check file or message, they are not dereferenced and 
   * the printf functions will printf them as the string (null) */   
  if( gLogFile == NULL ){
    return;
  }
    
  /* Lock the log file such that if other threads attempt to access it they will
   * block here until the lock is released
   */
  if( flock(gLogFileFd, LOCK_EX) ){
    printf("Error: Failed to get lock to log file\n");
    return;
  }
  

      
  /* Log the message to the log file */ 
  if( fprintf( gLogFile, "%s in %s : %i at %s\n", 
               message, file, line, timestamp ) 
               < 0 ){
    printf("Error: Something went wrong logging to the file\n");
  } 
  
  /* For some reason it is never writing to the file without this TODO */ 
  fflush(gLogFile);              
                   
  /* Unlock the log file such that other threads can once again utilize it */ 
  if( flock(gLogFileFd, LOCK_UN) ){
    printf("Error: Failed to unlock log file, logging to file will fail\n");
    return;
  }
  
  return; 
}

/* getTimestamp puts the current timestamp in the buffer pointer to by buff,
 * which is of buffBytesize. 
 *
 * Returns 0 on error, 1 on success.
 */
int getTimeStamp(char *buff, size_t buffBytesize)
{
  time_t    timeNow;
  struct tm gmTimeResult;
  
  /* Basic error checking */
  if( buff == NULL || buffBytesize == 0 ){
    printf("Error: Something was null in getTimeStamp\n");
    return 0; 
  }
  
  /* Get the current time as a time_t */
  timeNow = time(NULL); 
  if( timeNow == (time_t)-1 ){
    printf("Error: Failed to get timeNow\n");
    return 0;
  }
  
  /* Load the time_t to a tm struct */
  if( !gmtime_r(&timeNow, &gmTimeResult) ){
    printf("Error: Failed to get gmTimeResult\n");
    return 0; 
  }
  
  /* Obtain the timestamp as a string placed into buff */  
  if( !strftime(buff, buffBytesize, "%c", &gmTimeResult) ){
    printf("Error: Failed to get timestamp\n");
    return 0;
  }

  return 1;
}
