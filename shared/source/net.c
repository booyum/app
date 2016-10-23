#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/un.h> 

#include "logger.h"
#include "security.h"
#include "net.h"

enum{ SUN_PATH_BC = 108 }; 


/* getIncomingBc receives an incoming uint32_t that encodes the number of 
 * subsequent incoming bytes. Note that this assumes the interlocutor has 
 * sent such a uint32_t. This is the receive counterpart to the sendOutgoingBc 
 * function defined in this file.
 *
 * On success returns the number of incoming bytes as encoded. On error returns
 * 0. Note that it is not possible to tell between an error and 0 incoming 
 * bytes.
 */
uint32_t getIncomingBc(int socket)
{
  uint32_t incomingBc;
  
  /* Ensure that the socket is valid */
  if( socket == -1 ){
    logErr("Socket passed to getIncomingBc is invalid");
    return 0;
  }
  
  /* Receive the uint32_t from the socket */
  if( recv(socket, &incomingBc, sizeof(uint32_t), 0) != sizeof(uint32_t) ){
    logErr("Failed to receive incoming byte count");
    return 0;
  }
  
  /* Return the uint32_t in host order */
  return ntohl(incomingBc); 
}

/* sendOutgoingBc transmits a network ordered uint32_t equal to outgoingBc 
 * over the socket, it is intended for signaling to the interlocutor the 
 * subsequent byte count being sent over the socket, and it has as its 
 * counterpart getIncomingBc. 
 *
 * Returns 1 on success, 0 on error.
 */  
int sendOutgoingBc(int socket, uint32_t outgoingBc)
{
  /* Ensure that the socket is valid */
  if( socket == -1 ){
    logErr("Socket passed to sendOutgoingBc is invalid");
    return 0;
  }
  
  /* Signaling that you are sending 0 subsequent bytes is not supported */
  if( outgoingBc == 0 ){
    logErr("Signaling that you are sending 0 subsequent bytes is not valid");
    return 0;
  }
  
  /* Encode the uint32_t to network order */
  outgoingBc = htonl(outgoingBc);
  
  /* Send the network encoded uint32_t over the socket */
  if( send(socket, &outgoingBc, sizeof(uint32_t), 0) != sizeof(uint32_t) ){
    logErr("Failed to send the outgoing byte count");
    return 0;
  }
  
  return 1; 
}

/* ipv4Listen creates a socket listening on an ipv4 addr:port.
 * Returns the listening socket on success, on error returns -1.
 */  
int ipv4Listen(const char *addr, uint16_t port)
{
  struct in_addr     formattedAddr;
  struct sockaddr_in bindInfo;
  int                ipv4Sock;
  
  /* Basic error checking */
  if( addr == NULL ){
    logErr("Something was NULL that shouldn't have been");
    return -1;
  }
  
  /* Get the socket */
  ipv4Sock = socket(AF_INET, SOCK_STREAM, 0);
  if( ipv4Sock == -1 ){
    logErr("Failed to get an ipv4 socket");
    return -1;
  }
  
  /* Convert addr string to network byte order in formattedAddr */
  if( !inet_aton(addr, &formattedAddr) ){
    logErr("Failed to convert IP bind address to network order");
    return -1;
  }
  
  /* ipv4, network ordered port, network ordered ipv4 address (man 7 ip) */
  bindInfo.sin_family      = AF_INET;
  bindInfo.sin_port        = htons(port);
  bindInfo.sin_addr.s_addr = formattedAddr.s_addr; 
  
  /* Bind the socket to addr:port */
  if( bind(ipv4Sock, (const struct sockaddr *)&bindInfo, sizeof(bindInfo)) ){
    logErr("Failed to bind to address");
    return -1;
  }
  
  /* Begin listening on the socket */
  if( listen(ipv4Sock, SOMAXCONN) ){
    logErr("Failed to listen on socket");
    return -1; 
  }
  
  return ipv4Sock;
}




/* listenUds returns a bound and listening Unix Domain Socket on the path 
 * pointed to by path, or otherwise -1 on error
 */
int udsListen(char *path, int bc)
{
  struct sockaddr_un local;
  int                unixSock;
  
  /* Basic error checking */
  if( path == NULL || bc == 0 ){
    logErr("Something was NULL that shouldn't have been");
    return -1;
  }
  
  /* Path + NULL terminator must be under 108 bytes */
  if( bc + 1 > SUN_PATH_BC ){
    logErr("Path byte count is too large for unix domain socket");
    return -1; 
  }
  
  /* Get the Unix Domain Socket */
  unixSock = socket(AF_UNIX, SOCK_STREAM, 0);
  if( unixSock == -1 ){
    logErr("Failed to create a Unix Domain Socket");
    return -1; 
  }
  
  /* Bind the Unix Domain Socket */
  local.sun_family = AF_UNIX;
  if( !secStrCpy(local.sun_path, path, SUN_PATH_BC) ){
    logErr("Failed to copy path to sockaddr_un for unix domain socket");
    return -1; 
  }
  
  /* Remove the file if it exists (not checking return value as it may not) */
  unlink(local.sun_path);
  
  /* Bind the socket */
  if( bind(unixSock, (struct sockaddr *)&local, bc + sizeof(local.sun_family)) ){
    logErr("Failed to bind unix domain socket");
    return -1; 
  }
  
  /* Start listening */
  if( listen(unixSock, 20) ){
    logErr("Failed to listen on Unix Domain Socket");
    return -1;
  }
  
  return unixSock;
}


/* udsConnect establishes a connection to the Unix Domain Socket at the path 
 * pointed to by udsPath, of bc bytes long (not including terminating NULL). 
 * 
 * On success the established socket is returned, on error -1.
 */ 
int udsConnect(char *udsPath, unsigned int bc)
{
  int                unixSock;
  struct sockaddr_un remote;
  
  /* Basic error checking */
  if( udsPath == NULL || bc == 0 ){
    logErr("Something was NULL that shouldn't have been");
    return -1; 
  }
  
  /* Ensure that the NULL terminated path to the unix domain socket can fit in
   * the remote.sun_path buffer.
   */ 
  if( bc + 1 > SUN_PATH_BC ){
    logErr("path bytecount for unix domain socket too large, would truncate");
    return -1; 
  }
  
  /* Get a unix domain socket */
  unixSock = socket(AF_UNIX, SOCK_STREAM, 0);
  if( unixSock == -1 ){
    logErr("Failed to establish a unix domain socket for redirector connection");
    return -1; 
  }
  
  /* Set that we are connecting to a unix domain socket */
  remote.sun_family = AF_UNIX;
  
  /* Copy the path to the remote unix domain socket to our struct */ 
  if( !secStrCpy(remote.sun_path, udsPath, SUN_PATH_BC) ){
    logErr("Failed to copy unix domain socket path to the sockaddr_un struct");
    close(unixSock);
    return -1; 
  }
  
  /* Establish the connection to the remote unix domain socket */ 
  if( connect(unixSock, (struct sockaddr *)&remote, bc + sizeof(remote.sun_family)) ){
    logErr("Failed to connect to Tor redirector on unix domain socket");
    close(unixSock); 
    return -1; 
  }
  
  return unixSock;
}
