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


enum{ CONTROL_PORT_TOKEN_BC = 32 };

/* Singleton closure */
static char *gToken   = NULL;

static int establishConnection(void);
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
  sock = establishConnection();
  if( sock == -1 ){
    printf("Error: Failed to establish a connection to control port\n");
    return -1;
  }
  
  /* Authenticate over the connected control port */  
  if( !cpAuthenticate(sock) ){
    printf("Error: Failed to authenticate over the control port\n");
    return -1; 
  }
  
  /* If we made it here all is good, return the socket */ 
  return sock; 
}


static int establishConnection(void)
{
  struct sockaddr_un remote;
  int                len;
  int                ret;
  int                sock;  
  
  /* Get the socket for the control port connection */ 
  sock = socket(AF_UNIX, SOCK_STREAM, 0);
  if( sock == -1 ){
    printf("Error: Failed to get a control port socket\n");
    return -1;
  }
  
  /* Initialize the state required to make the connection */
  remote.sun_family = AF_UNIX;
  strcpy(remote.sun_path, "sandbox/control_unix_socket"); 
  len = strlen(remote.sun_path) + sizeof(remote.sun_family);
  
  /* Keep trying to make a control port connect until one is established or 
   * there is an error other than the error that the control port isn't ready
   * yet
   */ 
  do{
    errno = 0;
    ret = connect(sock, (struct sockaddr *)&remote, len);
    if( ret == -1 ){
      printf("Error: Failed to connect to control port\n");
      continue; 
    }
    printf("WORKED\n"); //TODO TODO TODO
  }while(ret); 
  
  
  return sock;
}

/* First byte sent is byte count of token, followed by the token */ 
static int cpAuthenticate(int sock)
{
  uint32_t authed    = 0;   
  
  
  if( sock == -1 ){
    printf("Error: The socket is not valid for control port\n");
    return 0;
  }
  
  
  /* Transmit the token */
  int ret =  send( sock, gToken, CONTROL_PORT_TOKEN_BC, 0);
  printf("\nERR: %i\n", errno);
  printf("SOCK %i\n", sock); 
  if( ret != CONTROL_PORT_TOKEN_BC ){
    printf("Error: Failed to send the authentication token over control socket\n");
    return 0;
  }
  
  int test = recv( sock, &authed, sizeof(authed), 0 );
  if( test == -1) printf("ERR RECV: %i\n", errno); 
  printf("recv bytesize %i\n", test); 
  /* Receive authentication status */ 
  if(  test != sizeof(authed) ){
    printf("Error: Failed to receive control port authentication status\n");
    return 0;
  } 
  
  authed = ntohl(authed);
  
  printf("\nAUTHED %u\n", authed);
  fflush(stdout);
  
  return(authed == 1); 
}
