#include <stdio.h> //for printf
#include <string.h> //for strlen

#include "isolProc.h"
#include "isolFs.h"
#include "isolKern.h"
#include "isolName.h"
#include "isolIpc.h" 
#include "isolNet.h"

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

/* TODO READD GUI ISOLATION */ 

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
  unsigned char *buff = secAlloc(1000); 


  logMsg("TEST"); 

  routerObj *testRouter = newRouter();
  if( testRouter == NULL ){
    logErr("Failed to make test router new");
    return -1;
  }

  if( !testRouter->methods->torConnect(testRouter) ){
    logErr("Failed to make ipv4 connection");
    return -1;
  }
  
  
  if( !testRouter->methods->socks5Relay(testRouter, "ruger.com", strlen("ruger.com"), 80) ){
    logErr("Failed to handshake");
    return -1; 
  } 
    
   
    
  if( !testRouter->methods->transmit(testRouter, "GET /index.html HTTP/1.1\r\nHost: ruger.com\n\n", 
                                     strlen("GET /index.html HTTP/1.1\r\nHost: ruger.com\n\n") )){
                                       logErr("transmit failed");
                                       return 0; 
                                     }
                                                                     
  if( !testRouter->methods->receive(testRouter, buff, 10) ){
    logErr("Failed to receive bytes");
    return -1;
  } 
  
    printf("ret: %s\n", buff); 
  fflush(stdout);
  
    if( !testRouter->methods->transmit(testRouter, "GET /index.html HTTP/1.1\r\nHost: ruger.com\n\n", 
                                     strlen("GET /index.html HTTP/1.1\r\nHost: ruger.com\n\n") )){
                                       logErr("transmit failed");
                                       return 0; 
                                     }
                                     
                                       if( !testRouter->methods->receive(testRouter, buff, 10) ){
    logErr("Failed to receive bytes");
    return -1;
  } 
  
  printf("ret: %s\n", buff); 
  fflush(stdout);
  
  
  return 0;
}



