#include <stdio.h>
#include <sys/types.h>         
#include <sys/socket.h>
#include <string.h>
#include <stdlib.h>

#include <sys/mman.h>
#include <sched.h>
#include <sys/types.h>         
#include <sys/socket.h>
#include <string.h>
#include <netdb.h>
#include <sys/un.h>
#include <errno.h> 
#include <unistd.h> 

extern "C"{
  #include "logger.h"
  #include "net.h"
}

enum{ CONTROL_PORT_TOKEN_BC = 32 };

/* Singleton closure */
static char *gToken;

 
static int cpAuthenticate(int sock);

/* Initialize control port connection, returns authenticated socket */
int initContPortCon(char *contPortToken)
{
  int sock;  
  
  /* Initialize the token and tokenBc singleton variables if they haven't been */ 
  if( gToken == NULL ){
    gToken = contPortToken; 
  }
  
  /* Establish the control port connection */
  sock = udsConnect( "sandbox/control_unix_socket", 
                     strlen("sandbox/control_unix_socket") );
  if( sock == -1 ){
    logErr("Failed to establish a connection to control port");
    return -1;
  }
  
  /* Authenticate over the connected control port */  
  if( !cpAuthenticate(sock) ){
    logErr("Failed to authenticate over the control port");
    return -1; 
  }
  
  /* If we made it here all is good, return the socket */ 
  return sock; 
}



/* First byte sent is byte count of token, followed by the token */ 
static int cpAuthenticate(int sock)
{
  uint32_t authed = 0;   
  
  
  if( sock == -1 ){
    logErr("The socket is not valid for control port");
    return 0;
  }
  
  
  /* Transmit the token */
  if(  send( sock, gToken, CONTROL_PORT_TOKEN_BC, 0) != CONTROL_PORT_TOKEN_BC ){
    logErr("Failed to send the authentication token over control socket");
    return 0;
  }
  
  /* receive authentication status */ 
  if( recv( sock, &authed, sizeof(authed), 0 ) != sizeof(authed) ){
    logErr("Failed to receive control port authentication status\n");
    return 0; 
  }
  
  
  authed = ntohl(authed);
  
  printf("\nAUTHED %u\n", authed);
  fflush(stdout);
  
  return(authed == 1); 
}
