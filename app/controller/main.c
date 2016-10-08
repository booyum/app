#include <stdio.h> //for printf
#include <string.h> //for strlen

#include "isolProc.h"
#include "isolFs.h"
#include "isolKern.h"
#include "isolName.h"
#include "isolIpc.h" 
#include "isolNet.h"
#include "isolGui.h"

#include "security.h"
#include "logger.h"
#include "prng.h" 
#include "router.h" 


static int initialize();
static int isolatedMain(void);

int main()
{
  /* Initialize the PRNG (note we must NOT be isolated into sandbox dir) */ 
  if( !initializePrng() ){
    logErr("Failed to initialize the PRNG");
    return 0;
  }

  if( !isolGui() ){
    logErr("Failed to isolate the GUI");
    return 0; 
  }

  /* Isolate the process and resume execution at initialize */ 
  isolProc(&initialize);
  return 0; 
}



static int initialize()
{
/* Note that isolNet is called after all functions other than isolKern so that
 * the spawned redirector process is also isolated, however it uses its own 
 * kernel isolation and therefore isolKern is called after it. 
 */ 

  /* Isolate the process to the sandbox directory (new root on Unix) */ 
  if( !isolFs() ){
    logErr("Failed to isolate the filesystem");
    return 0; 
  }

  /* Initialize the logger (note that we must be isolated into sandbox dir) */
  if( !initLogFile("log") ){
    logErr("Failed to initialize log file");
    return 0; 
  }

  /* Isolate the process from system names */
  if( !isolName() ){
    logErr("Failed to isolate from system names");
    return 0;
  }
  
  /* Isolate the process from IPC */
  if( !isolIpc() ){
    logErr("Failed to isolate from IPC");
    return 0; 
  }
  
  /* Isolate the process from the network */
  if( !isolNet() ){
    logErr("Failed to isolate the network");
    return 0;
  }
  
  
  /* Isolate the process from kernel functionality */ 
  if( !isolKern() ){
    logErr("Failed to isolate kernel functionality");
    return 0; 
  }
  
  /* Begin the actual application logic from isolatedMain */ 
  return isolatedMain(); 
}


static int isolatedMain(void)
{
  
  return 0;
}



