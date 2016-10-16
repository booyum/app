#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/un.h> //need unix 

#include "router.h"
#include "security.h"
#include "logger.h"

/* Object Prototype */ 
typedef struct privateRouter{
  routerObj   publicRouter;
  int         socket; 
}privateRouter;

/** Public Methods **/
static int reinitialize(routerObj *this);
static int destroyRouter(routerObj **thisPointer);
static int receive(routerObj *this, void *buff, uint32_t bytesRequested);
static uint32_t getIncomingBytesize(routerObj *this);
static int transmit(routerObj *this, void *buff, uint32_t bytesToSend);
static int transmitBytesize(routerObj *this, uint32_t bytesize);
static int socks5Relay(routerObj *this, char *addr, uint8_t addrBytesize, uint16_t port);
static int torConnect(routerObj *this);
static int ipv4Listen(routerObj *this, char *addr, uint16_t port);
static int getConnection(routerObj *this);
static int setSocket(routerObj *this, int socket);

/**  Private Methods **/ 
static int socks5Handshake(routerObj *this);
static int socks5Request(routerObj *this, char *addr, uint8_t bytes, uint16_t port);
static int socks5ValidateResponse(routerObj *this);

/* Construct private methods */ 
static routerClassMethods *setClassMethods(void);





/* Global Statics */
static routerClassMethods *gClassMethods;

/* Externs, from isolate.c for the mprotected tor sockaddr struct */
extern struct sockaddr *gTorSockAddr; 
extern socklen_t gTorAddrLen; 


/**********************************CONSTRUCTOR*********************************/


/* newRouter allocates a new router object with encoded public method pointers.
 * It returns the private router object cast to a public router object, or NULL
 * on error.  
 */
routerObj *newRouter(void)
{
  privateRouter *construct;
  
  /* Allocate the new objects memory */
  construct = secAlloc(sizeof(*construct)); 
  if(construct == NULL){
    logErr("Failed to allocate memory for router object"); 
    return NULL;  
  }
  
  /* Set this instances methods to those of the class */   
  construct->publicRouter.methods = setClassMethods();  
  if( construct->publicRouter.methods == NULL ){
    logErr("Failed to allocate vTable for router Object");
    return NULL; 
  }
   
  /* Initialize the objects private properties */ 
  construct->socket = -1; 
  
  /* Return the private object cast as a public object, this is an 
   * implementation of DCL12-C */ 
  return (routerObj *) construct; 
}



/********************************PUBLIC METHODS********************************/


static routerClassMethods *setClassMethods(void) 
{
  if(gClassMethods != NULL) return gClassMethods; 
  
 
  gClassMethods = allocMemoryPane( sizeof(routerClassMethods) ); 
  if( gClassMethods == NULL ){
    logErr("Failed to allocate memory backing for router class methods");
    return NULL;
  }
  
  gClassMethods->transmit            = &transmit;
  gClassMethods->transmitBytesize    = &transmitBytesize;
  gClassMethods->receive             = &receive; 
  gClassMethods->socks5Relay       = &socks5Relay;
  gClassMethods->getIncomingBytesize = &getIncomingBytesize;
  gClassMethods->torConnect         = &torConnect; 
  gClassMethods->ipv4Listen          = &ipv4Listen;
  gClassMethods->getConnection       = &getConnection;
  gClassMethods->setSocket           = &setSocket; 
  gClassMethods->destroyRouter       = &destroyRouter;
  gClassMethods->reinitialize        = &reinitialize; 

  if( !freezeMemoryPane(gClassMethods, sizeof(routerClassMethods)) ){
    logErr("Failed to freeze the vTable for the router object");
    free(gClassMethods);
    return NULL;  
  }

  return gClassMethods;
}



/* reinitialize closes the current socket and resets the router to a new state.
 * returns 0 on error, 1 on success. 
 */
static int reinitialize(routerObj *this)
{
  privateRouter *private = (privateRouter *)this;
  
  /* Basic error checking + function pointer encode */
  if( this == NULL ){
    logErr("Something was NULL that shouldn't have been");
    return 0;
  }
  
  /* If the socket was already -1 then reinitialization did nothing */ 
  if( private->socket == -1 ){
    logWrn("Attempted to reinitialize a router that was in default state");
    return 1; 
  }
  
  /* Close the socket */
  if( close(private->socket) ){
    logErr("Failed to close the routers socket");
    return 0;
  }
  
  /* Reset the socket to -1 */ 
  private->socket = -1; 
  
  return 1; 
}

/*
 * destroyRouter closes the routers socket if it is open, and then securely 
 * frees the memory associated with the object. 
 *
 * returns 0 on error, 1 on success. 
 */
static int destroyRouter(routerObj **thisPointer)
{
  privateRouter *deconstruct;
  
  /* Basic error checking + correct cast */ 
  if( thisPointer == NULL || *thisPointer == NULL ){
    logErr("Something was NULL that shouldn't have been");
    return 0; 
  }
  
  deconstruct = (privateRouter *) *thisPointer;   
   
  /* Close the socket if it is open */  
  if( deconstruct->socket != -1 && close(deconstruct->socket) ){
    logErr("Failed to close Socket"); 
    return 0; 
  }

  /* Free the router object */ 
  if( !secFree((void**)&deconstruct, sizeof(privateRouter)) ){ 
    logErr("Failed to free memory of router object");
    return 0;
  }

  return 1; 
}


/* recieve receives bytesRequested from the socket associated with the
 * router object this and puts them into the buffer pointer to by buff.
 *
 * returns 0 on error, 1 on success.  
 */
static int receive(routerObj *this, void *buff, uint32_t bytesRequested)
{
  privateRouter *private = (privateRouter *)this;
  
  ssize_t recvReturn;
 
  /* Basic error checking + function pointer encode */
  if( this == NULL ){ 
    logErr("Something was NULL that shouldn't have been"); 
    return 0; 
  }
  
  /* Can only receive on an established socket */ 
  if( private->socket == -1 ){
    logErr("This router hasn't a valid socket associated with it"); 
    return 0; 
  }
  
  /* Keep receiving bytes to buff until bytesRequested are received */ 
  for( ; bytesRequested ; buff += recvReturn, bytesRequested -= recvReturn){
  
  
    recvReturn = recv( private->socket, buff, bytesRequested, 0);
    
    if(recvReturn < 1){
      logErr("Failed to receive bytes");
      return 0;
    }
  }
  
  return 1;
}

/* getIncomingBytesize receives an incoming uint32_t that encodes the number of 
 * subsequent incoming bytes. Note that this assumes that the interlocutor 
 * has sent such a uint32_t. This is the receive counterpart to the 
 * transmitBytesize function defined in this file.
 *
 * Returns 0 on error or incoming byte count representing 0, 1 on success.  
 */
static uint32_t getIncomingBytesize(routerObj *this)
{
  /* Note that incomingBytesize is written to with a pointer and must be 
   * initialized */
  uint32_t incomingBytesize = 0;

  /* Basic error checking + function pointer encode */ 
  if( this == NULL ){
    logErr("Something was NULL that shouldn't have been");  
    return 0; 
  }
    
  /* Receive from interlocutor a uint32_t conveying the incoming byte count */
  if( !this->methods->receive(this, &incomingBytesize, sizeof(uint32_t)) ){
    logErr("Failed to receive incoming bytesize"); 
    return 0; 
  }

  /* return the host encoded incoming bytesize */
  return ntohl(incomingBytesize);
}

/* transmit sends bytesToSend bytes from the buffer pointed to by buff over the
 * private socket of the router object this.
 *
 * returns 0 on error, 1 on success. 
 */
static int transmit(routerObj *this, void *buff, uint32_t bytesToSend)
{
  privateRouter *private = (privateRouter *)this;

  ssize_t sendReturn;
   
  /* Basic error checking + function pointer encode */ 
  if(this == NULL || buff == NULL){
    logErr("Something was NULL that shouldn't have been"); 
    return 0;
  }
   
  /* Only transmit on an established socket */
  if(private->socket == -1){
    logErr("Router hasn't a socket set"); 
    return 0;
  }
  
  /* send bytesToSend bytes from buff over private->socket */ 
  for( ; bytesToSend ; buff += sendReturn, bytesToSend -= sendReturn){
    sendReturn = send(private->socket, buff, bytesToSend, 0); 
    if(sendReturn < 0){
      logErr("Failed to send bytes"); 
      return 0;
    } 
  }
 
 return 1; 
}

/* transmitBytesize encodes bytesize to network order and transmits it over the
 * private socket associated with the this router object. 
 *
 * This function is intended for use with getIncomingBytesize.
 *
 * Returns 0 on error, 1 on success. 
 */
static int transmitBytesize(routerObj *this, uint32_t bytesize)
{
  privateRouter *private = (privateRouter *)this;

  uint32_t bytesizeEncoded;
  
  /* Basic error checking + function pointer encoding */
  if(this == NULL || bytesize == 0){
    logErr("Something was NULL that shouldn't have been"); 
    return 0;
  }
 
  /* Can only transmit over initialized socket */ 
  if(private->socket == -1){
    logErr("Router hasn't a socket set"); 
    return 0; 
  }
  
  /* encode the bytesize to network order */
  bytesizeEncoded = htonl(bytesize);
  
  /* transmit the bytesize over the connected socket */ 
  if( !this->methods->transmit(this, &bytesizeEncoded, sizeof(uint32_t)) ){
    logErr("Failed to transmit bytesize"); 
    return 0; 
  }
  
  return 1; 
}

/* socks5Relay establishes a socks 5 connection to addr:port
 *
 * The socket associated with the routerObj this, returned by the socket() 
 * syscall, must already be connected to the socks port of a socks 5 proxy via 
 * the connect() syscall, both of which are accomplished with the torConnect()
 * method of the router object (with the appropriate arguments). 
 * 
 * See also: socks5Handshake, socks5Request, and 
 * socks5ValidateResponse
 *
 * Reference: https://www.ietf.org/rfc/rfc1928.txt
 *
 * Returns 0 on error, 1 on success. 
 */
static int socks5Relay(routerObj *this, char *addr, uint8_t addrBytesize, uint16_t port)
{  
  privateRouter *private = (privateRouter *)this; 
  
  /* Basic error checking + function pointer encode */
  if( this == NULL || addr == NULL || addrBytesize == 0){
    logErr("Something was NULL that shouldn't have been"); 
    return 0;
  }
    
  /* Need a socket already connected to a Socks 5 Proxy */
  if( private->socket == -1 ){
    logErr("No socket established for router"); 
    return 0; 
  }
    
  /* Engage in the socks 5 handshake */
  if( !socks5Handshake(this) ){
    logErr("Socks 5 handshake with Socks Server failed"); 
    return 0;
  }

  /* Engage in the socks 5 request protocol */
  if( !socks5Request(this, addr, addrBytesize, port) ){
    logErr("Failed to send socks request to Socks Server"); 
    return 0;
  }
  
  /* Ensure the request was successful */
  if( !socks5ValidateResponse(this) ){
    logErr("Socks 5 request was processed by Socks Server but failed"); 
    return 0;    
  }
   
  return 1; 
}

/* torConnect establishes a Unix Domain Socket to the redirector that connects
 * to Tor. 
 *
 * Returns 0 on error, 1 on success. 
 */
static int torConnect(routerObj *this)
{
  privateRouter *private = (privateRouter *)this;
  
  /* Basic error checking */ 
  if( private == NULL ){
    logErr("Something was NULL that shouldn't have been");
    return 0; 
  }
  
  if(private->socket != -1){
    logErr("Router already in use"); 
    return 0; 
  }

  /* Set the socket of this router to the return value of the socket syscall. 
   * Note passing 0 to socket for protocol, this should be fine since TCP is
   * essentially always the default for SOCK_STREAM */
  if( !this->methods->setSocket(this, socket(AF_UNIX, SOCK_STREAM, 0)) ){
    logErr("Failed to set socket"); 
    return 0;
  }
  
  /* Make sure that the socket was actually created successfully */
  if(private->socket == -1){
    logErr("Failed to create new socket"); 
    return 0; 
  } 
  

  /* TODO Make nice and cross platform  TESTING ONLY*/
  int len; 
  struct sockaddr_un remote;
  remote.sun_family = AF_UNIX;
    strcpy(remote.sun_path, "/tor_unix_socket");
    len = strlen(remote.sun_path) + sizeof(remote.sun_family);
  /* TODO TODO TODO */
  
  /* Establish the connection to addr:port */
  if( connect(private->socket, (struct sockaddr *)&remote, len) ){
    logErr("Failed to connect to Tor"); 
    return 0; 
  }
     
  return 1; 
}


/* ipv4Listen puts the router into a listening state by creating a socket bound
 * to addr:port and listening on. 
 *
 * Returns 0 on error and 1 on success
 */
static int ipv4Listen(routerObj *this, char *addr, uint16_t port)
{
  privateRouter *private = (privateRouter *)this;
  
  struct in_addr     formattedAddress;
  struct sockaddr_in bindInfo;
  
 
  /* Basic error checking + function pointer encode */
  if(this == NULL || addr == NULL){
    logErr("Something was NULL that shouldn't have been"); 
    return 0;
  }
  
  /* Make sure that the routers socket is not already initialized */
  if(private->socket != -1){
    logErr("Router already in use"); 
    return 0; 
  }
  
  /* Set the socket of this router to the return value of the socket syscall. 
   * Note passing 0 to socket for protocol, this should be fine since TCP is
   * essentially always the default for SOCK_STREAM */
  if( !this->methods->setSocket(this, socket(AF_INET, SOCK_STREAM, 0)) ){
    logErr("Failed to set socket"); 
    return 0; 
  }

  /* Make sure that the socket was actually created successfully */
  if(private->socket == -1){
    logErr("Failed to create socket"); 
    return 0; 
  }
  
  /* Convert addr string to network byte ordered binary pointed to by 
   * formattedAddress */
  if( !inet_aton((const char*)addr , &formattedAddress) ){
    logErr("Failed to convert IP bind address to network order");  
    return 0; 
  }
  
  /* ipv4, network ordered port, network ordered binary ipv4 address 
   * representation, see man 7 ip for bindInfo struct details */
  bindInfo.sin_family      = AF_INET;
  bindInfo.sin_port        = htons(port);
  bindInfo.sin_addr.s_addr = formattedAddress.s_addr; 
  
  /* Bind the socket to addr:port */ 
  if( bind(private->socket, (const struct sockaddr*) &bindInfo, sizeof(bindInfo)) ){
    logErr("Failed to bind to address"); 
    return 0; 
  }
 
  /* Begin listening on the socket */ 
  if( listen(private->socket, SOMAXCONN) ){
    logErr("Failed to listen on socket"); 
    return 0; 
  }
  
  return 1; 
}

/* getConnection gets a connection from the listening socket of the router, 
 * which must already be initialized with ipv4Listen.
 *
 * Returns -1 on error, on success a new socket for the connected client. 
 */
static int getConnection(routerObj *this)
{
  privateRouter *private = (privateRouter *)this;
  
  /* Basic error checking + function pointer encode */
  if( this == NULL ){
    logErr("Error: Something was NULL that shouldn't have been");
    return -1;
  }

  /* The socket must already be initialized in a bound + listening state */ 
  if( private->socket == -1 ){
    logErr("Error: Uninitialized socket, cannot accept");
    return -1; 
  }
 
  return accept(private->socket, NULL, NULL); 
}

/* setSocket sets the socket of the router object this to the value given
 * as an argument for the socket parameter. 
 *
 * Returns 0 on error, 1 on success. 
 */
static int setSocket(routerObj *this, int socket)
{
  privateRouter *private = (privateRouter *)this;
  
  /* Basic error checking + function pointer encode */
  if( private == NULL ){
    logErr("Error: Something was NULL that shouldn't have been\n");
    return 0; 
  }
  
  private->socket = socket;
  
  return 1; 
}


/*****************************PRIVATE METHODS**********************************/

/* socks5Handshake engages in the initial Socks 5 handshake with the 
 * Socks Proxy, which the router must already be connected to. Note that this
 * implementation of Socks does not support authentication, and only supports
 * Socks 5. 
 *
 * Reference: https://www.ietf.org/rfc/rfc1928.txt 
 *
 * Returns 0 on error, 1 on success. If the Socks Proxy doesn't support a lack
 * of authentication or Socks 5, error will be returned. Eventually may 
 * implement authenticated Socks 5.  
 */
static int socks5Handshake(routerObj *this)
{ 
  char proxyResponse[2]; 
  
  /* Basic error checking */
  if( this == NULL ){
    logErr("Error: Something was NULL that shouldn't have been");
    return 0;
  }
  
  /* Transmit the byte sequence indicating Socks 5, one method, only 
   * unauthenticated */   
  if( !this->methods->transmit(this, "\005\001\000", 3) ){
    logErr("Failed to transmit bytes to socks server during initialization");
    return 0;
  }
  
  /* Receive the response from the Socks server */
  if( !this->methods->receive(this, proxyResponse, 2) ){
    logErr("Failed to get response from proxy");
    return 0;
  }
  
  /* Ensure that the Socks server supports version 5 and a lack of 
   * authentication */
  if( proxyResponse[0] != 5 ){
    logErr("Socks proxy doesn't support Socks5");
    return 0;
  }
  
  if( proxyResponse[1] != 0 ){
    logErr("Socks proxy doesn't support a lack of authentication");
    return 0;
  }
  
  return 1; 
}

  
/* socks5Request engages in the second part of the Socks 5 protocol,
 * primarily attempting to establish a connection to addr:porn through the Socks
 * proxy. 
 *
 * Reference: https://www.ietf.org/rfc/rfc1928.txt
 *
 * Client Request Format:
 *
 * +----+-----+-------+------+----------+----------+
 * |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
 * +----+-----+-------+------+----------+----------+
 * | 1  |  1  | X'00' |  1   | Variable |    2     |
 * +----+-----+-------+------+----------+----------+
 *  
 * Note that this function expects addr to be a URL, this function does not
 * currently support Socks connections to IP addresses, however this is 
 * something TODO in the future. 
 *
 * Returns 0 on error and 1 on success. 
 */
static int socks5Request(routerObj *this, char *addr, uint8_t bytes, uint16_t port)
{
  unsigned int fixedSocksBytes = 1 + 1 + 1 + 1 + 1 + 2; //reference diagram 
  char         socksRequest[fixedSocksBytes + 255];     //(2^8 - 1) = 255, 
                                                        //max uint8_t 
  
  /* Basic error checking */
  if(this == NULL || addr == NULL){
    logErr("Something was NULL that shouldn't have been"); 
    return 0; 
  }
  
  /* format the destination port in network order in accordance with RFC */
  port = htons(port);
  
  /* with || denoting concatenation and [x] denoting of x bytes: 
  *
  *  socks version five [1] || connect [1] || RSV is NULL [1] || 
  *  addr is domain not IP [1] || prepend addr with bytesize as octet [1] ||
  *  addr [var bytes] || destination port in network octet order [2]    
  */
  memcpy(&socksRequest[0], "\005\001\000\003", 4);
  memcpy(&socksRequest[4], &bytes, 1);
  memcpy(&socksRequest[5], addr, bytes);
  memcpy(&socksRequest[5 + bytes], &port, 2);
  
  /* Initialize the Socks 5 Connection */  
  if( !this->methods->transmit(this, socksRequest, fixedSocksBytes + bytes) ){
    logErr("Failed to transmit message to socks server"); 
    return 0;
  }
    
  return 1; 
}

/*
 * socks5ValidateResponse gets the final response from the socks server and 
 * ensures that everything has gone correctly.
 * 
 * reference https://www.ietf.org/rfc/rfc1928.txt
 * 
 * returns 0 on error (or failure) and 1 on success. 
 * 
 */
static int socks5ValidateResponse(routerObj *this)
{
  /* For holding responses from the Socks Proxy. As this is currently 
   * implemented, no more than 18 bytes will ever be written to this
   * buffer, first four bytes to get up to ATYP (see diagram below),
   * then based on the value of ATYP, and from the start of the buffer,
   * either 4 or 16 octets will be written as BND.ADDR followed by the
   * 2 bytes from BND.PORT. 
   *
   * In the spirit of better safe than sorry, taking into consideration that
   * "domain" indicating ATYPs with variable sized BND.ADDRs are not implemented 
   * yet, to ensure this will not overflow into the future, the array is 
   * oversized to 261 bytes, which is 255 + 2 + 1 + 1 + 1 + 1, and the largest 
   * buffer that would ever be required for any implementation of this function.  
   */ 
  char proxyResponse[261];
  
  /* Basic error checking */
  if(this == NULL){
    logErr("Something was NULL that shouldn't have been"); 
    return 0; 
  }
  
  /* PROXY RESPONSE FORMAT
  * 
  * +----+-----+-------+------+----------+----------+
  * |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
  * +----+-----+-------+------+----------+----------+
  * | 1  |  1  | X'00' |  1   | Variable |    2     |
  * +----+-----+-------+------+----------+----------+
  */
  if( !this->methods->receive(this, proxyResponse, 4) ){
    logErr("Failed to receive proxy response"); 
    return 0; 
  }

  if(proxyResponse[0] != 5){
    logErr("Socks server doesn't think it is version 5"); 
    return 0; 
  }
  
  if(proxyResponse[1] != 0){
    logErr("Connection failed"); 
    return 0; 
  }
  
  /* proxyResponse[3] is ATYP and determines the bytesize of BND.ADDR.
   * if ATYP is 1, BND.ADDR is an IPv4 address encoded as 4 octets.
   * if ATYP is 3, BND.ADDR is a domain name of variable octets (unsupported)
   * if ATYP is 4, BND.ADDR is an IPv6 address encoded as 16 octets. 
   *
   * We don't really care about this, only that success was had, however,
   * we do want to make sure to clear the socket buffer 
   */ 
  switch(proxyResponse[3]){
    case 1:
      this->methods->receive(this, proxyResponse, 4 + 2);
      break;
    case 3:
      logErr("Currently not supporting Socks Proxies on domain names");
      return 0;
    case 4:
      this->methods->receive(this, proxyResponse, 16 + 2);
      break;
    default:
      logErr("Something unexpected happened with the Socks Proxy response");
      return 0; 
  }
  
   
  return 1; 
}
