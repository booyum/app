#include <stdio.h>
#include <sys/types.h>         
#include <sys/socket.h>
#include <string.h>

#include <sys/mman.h>
#include <sched.h>
#include <sys/types.h>         
#include <sys/socket.h>
#include <string.h>
#include <netdb.h>
#include <sys/un.h>

#include <errno.h>

#include "logger.h"
#include "security.h"
#include "controller.h"
#include "prng.h" 


enum{ CONTROL_PORT_TOKEN_BC = 32 };

static int authenticateCp(int cpIncoming);
static int manageControl(int cpIncoming);

static char *allocRandToken(void);


static char *sToken;
static int  sListenSocket; 
static int  sInitialized; 


/* initializeController prepares the main application logic to receive control 
 * packets from the front end controller (typically a GUI). It does this by 
 * initializing a singleton object, which has as its instance a random token 
 * pointed to by sToken, which is CONTROL_PORT_TOKEN_BC bytes long, which must be sent over
 * the listening control port, identified by sListenSocket, in order to obtain
 * a control session.
 *
 * This function allocates memory for the token and randomizes it, then it
 * creates the listening unix domain socket over which control sessions can
 * be accepted. On success 1 is returned and the singleton variable sInitialized 
 * is set to 1. On error 0 is returned and sInitialized will be kept at 0.  
 *
 * This function can only be called once per run of the application.
 */
int initializeController(void)
{
  struct sockaddr_un local;
  int                len;
  
  /* If sToken isn't NULL then this function was already called */ 
  if( sToken != NULL ){
    logErr("Reinitialization of controller is not supported");
    return 0; 
  }
  
  /* Generate the random token */ 
  sToken = allocRandToken();
  if( sToken == NULL ){
    logErr("Failed to allocate memory for controller token");
    return 0; 
  }
  
  /* Start listening for incoming control connections (not accepting yet!) */
  
  /* Get the Unix Domain Socket */ 
  sListenSocket = socket(AF_UNIX, SOCK_STREAM, 0);
  if( sListenSocket == -1 ){
    logErr("Failed to open a unix socket for redirector to listen");
    return 0;
  }
  
  /* Bind the Unix domain socket */
  local.sun_family = AF_UNIX; 
  secStrCpy(local.sun_path, "sandbox/control_unix_socket", 108); /* NOTE: See beej for 108 figure */ 
  
  /* Remove the file if it exists (not checking return value as it may not) */
  unlink(local.sun_path);
  
  /* Bind the socket and start listening, if either fails return -1 */
  len = strlen(local.sun_path) + sizeof(local.sun_family);
  if( bind(sListenSocket, (struct sockaddr *)&local, len) || 
      listen(sListenSocket, 20) ){ 
    return 0;
  }
  
  sInitialized = 1; 
  
  return 1;
}

/* allocRandToken generates a random token of CONTROL_PORT_TOKEN_BC bytes, which
 * by specification is 32 bytes. The alphabet for the random token consists of 
 * all lower case alphabetical ASCII characters, and additionally 0-5, for a 
 * total of a 32 character alphabet. The resultant token will be 32 characters 
 * from this 32 character alphabet. Note that mod skew is not an issue because 
 * of the properties of the alphabet and the use of an 8 bit unsigned integer,
 * however the resultant token will only contain 160 bits of randomness, which
 * is adequate. 
 *
 * allocRandToken returns a pointer to the heap allocated random token on 
 * success, or a NULL pointer on error. The tokens memory is frozen to read 
 * only, and it is protected with page guards. 
 */ 
static char *allocRandToken(void)
{
  static char alphabet[32] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
                              'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 
                              'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3',
                              '4', '5'};
  
  char     *token   = NULL;
  uint8_t  randByte = 0; 
  int      tracker  = 0;
  
  token = secAlloc(CONTROL_PORT_TOKEN_BC);
  if( token == NULL ){
    logErr("Failed to allocate memory for control port token");
    return NULL;
  }
  
  while(tracker != CONTROL_PORT_TOKEN_BC){
    if(!randomize((unsigned char*)&randByte, 1)){
      logErr("Failed to generate random token");
      return NULL;
    }
    token[tracker++] = alphabet[randByte % 32];
  }
  
  if( !freezeMemoryPane(token, CONTROL_PORT_TOKEN_BC) ){
    logErr("Failed to freeze the control port token to read only");
    return NULL; 
  }
  
  return token;
}


/* manageControlPort accepts incoming connections on the listening control port,
 * then it forks and manages the incoming connection with the child fork, and 
 * continues listening for new control sessions from the parent. 
 *
 * The child fork will authenticate the control session by ensuring that the 
 * connecting client has the secret control token, if it doesn't the connection
 * will be closed, otherwise control for the control session will be transfered 
 * to manageControl.
 *
 * This function returns 0 on error, otherwise it never returns.
 */ 
int manageControlPort(void)
{
  int cpIncoming;

  /* This should catch lack of, or failed, initialization */ 
  if( !sInitialized ){
    logErr("Attempt to manage control port without initialization detected");
    return 0; 
  }
  
  /* Wait for connections to the control port, then manage them */ 
  while( 1 ){
    /* Get the incoming control port connection */ 
    cpIncoming = accept(sListenSocket, NULL, NULL);
    if( cpIncoming == -1){
      printf("ACCEPT FAILED %i\n", errno);
      fflush(stdout); 
      continue;
    }
    
    /* Make a new thread for managing this control session */ 
    switch( fork() ){
      /* If we had an error forking go back and try a new connection */ 
      case -1:{
        logWrn("Failed to fork for the control port");
        continue;
      }
      
      /* The child handles this control session */
      case 0:{
      
        /* Make sure the connecting control client knows the control port token */
        if( !authenticateCp(cpIncoming) ){
          logWrn("Controller tried authenticating with incorrect token");
          close(cpIncoming);
          exit(-1); 
        }
        
        
        /* The control session has been authenticated, so let's manage it */
        if( !manageControl(cpIncoming) ){
          logWrn("Managing the control session failed");
          close(cpIncoming);
          exit(-1); 
        }
        
        /* Done managing control for this session, exit */  
        exit(0);
      }
      
      /* The parent continues waiting for new connections */
      default:{
        continue;
      }
      
    }
  } 
  
  /* We should never make it here */ 
  return 0; 
}


/* authenticateCp takes the incoming control connection and receives the first 
 * 4 bytes from it, which make up a unint32_t representing the size of the 
 * secret token the client will next transmit. If the size doesn't match what 
 * is expected, authentication will immediately fail.
 *
 * If the size is correct, this function will receive the token from the 
 * client over the socket, and then will compare it to the expected value of 
 * the token. If the authentication attempt matches the token, 1 will be returned,
 * otherwise 0 is returned.
 *
 * This function returns 0 on error as well as in cases in which authentication
 * failed, it returns 1 if authentication completed successfully.
 */  
static int authenticateCp(int cpIncoming)
{
  char *authAttempt; 
  
  uint32_t authSuccess = 1;
  uint32_t authFail = 0; 
  
  authSuccess = htonl(authSuccess);
  authFail    = htonl(authFail); 
  
  /* Make sure initialization has had success */ 
  if( !sInitialized ){
    logErr("Controller must be initialized to use authenticateCp");
    return 0; 
  }
  
  authAttempt = secAlloc( CONTROL_PORT_TOKEN_BC );
  if( authAttempt == NULL ){
    logErr("Failed to allocate memory to store authentication attempt");
    send( cpIncoming, &authFail, sizeof(authFail), 0);
    return 0; 
  }
  
  /* Receive the authentication token */
  
  if( recv(cpIncoming, authAttempt, CONTROL_PORT_TOKEN_BC, 0) != CONTROL_PORT_TOKEN_BC ){
    logWrn("Failed to get authentication token from client on control port");
    fflush(stdout); 
    send( cpIncoming, &authFail, sizeof(authFail), 0);
    secFree((void**)&authAttempt, CONTROL_PORT_TOKEN_BC);
    return 0; 
  }

  
  /* Ensure that the authentication attempt matches the token */
  if( !dataIndependentCmp((unsigned char *)sToken, (unsigned char *)authAttempt, CONTROL_PORT_TOKEN_BC) ){
    logWrn("Client had an incorrect control port token");
    fflush(stdout); 
    send( cpIncoming, &authFail, sizeof(authFail), 0);
    secFree((void**)&authAttempt, CONTROL_PORT_TOKEN_BC);
    return 0; 
  }
  

  
  /* Send '1' to the client to signal authentication was with success */
  if( send( cpIncoming, &authSuccess, sizeof(authSuccess), 0) != sizeof(authSuccess) ){
    logErr("Failed to send token byte count over control socket\n");
    fflush(stdout); 
    secFree((void**)&authAttempt, CONTROL_PORT_TOKEN_BC);
    return 0;
  } 

  
  
  secFree((void**)&authAttempt, CONTROL_PORT_TOKEN_BC);
  
  return 1;
}


/* manageControl manages the control session, which should have been authenticated */ 
static int manageControl(int cpIncoming)
{
  uint32_t controlAction = 0; 
  
  do{
    /* Receive the controlAction from the client */
    if( recv(cpIncoming, &controlAction, sizeof(controlAction), 0) != sizeof(controlAction) ){
      logWrn("Failed to get authentication token BC from client on control port");
      return 0; 
    }
    
    /* Control switch */ 
    switch( controlAction ){
      case 0:{
        logMsg("Client requested to close control session");
        close(cpIncoming);
        return 1;
      }
      
      default:{
        printf("Muahhahaa\n");
        fflush(stdout); 
        continue; 
      }
    }
  }while(1); 
}



/* Returns the pointer to the singletons secret token */ 
char *getToken(void)
{
  return sToken;
}

/* Returns the value of the singletons token byte count variable */ 
unsigned int getTokenBc(void)
{
  return CONTROL_PORT_TOKEN_BC; 
}
