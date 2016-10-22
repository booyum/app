#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdint.h>
#include <arpa/inet.h>

#include "logger.h"
#include "net.h"
#include "torCon.h"


static int socks5ValidateResponse(int socket);
static int socks5UrlCon(int socket, char *url, uint8_t bc, uint16_t port);
static int socks5Handshake(int socket);


/* torUrlCon is passed a socket connected to Tor's SocksPort, a URL, the byte
 * count of the URL, and a port, and it establishes a connect to the URL:PORT
 * over Tor.
 *
 * Returns 1 on success and the socket is connected to the URL:PORT, on 
 * error 0 is returned.  
 */
int torUrlCon(int torSocket, char *url, uint8_t bc, uint16_t port)
{
  /* Basic error checking */
  if( url == NULL || bc == 0 ){
    logErr("Something was NULL that shouldn't have been");
    return 0; 
  }
  
  /* Make sure the socket is valid */
  if( torSocket == -1 ){
    logErr("The socket passed to torUrlConnect was invalid");
    return 0;
  }
  
  /* Engage in the Socks 5 handshake */
  if( !socks5Handshake(torSocket) ){
    logErr("Failed to engage in the socks 5 handshake");
    return 0;
  }
  
  /* Request connection to url:port over Socks5 Proxy */
  if( !socks5UrlCon(torSocket, url, bc, port) ){
    logErr("Failed to make requested connection over Socks5 proxy");
    return 0; 
  }
  
  /* Ensure that the connection was established */
  if( !socks5ValidateResponse(torSocket) ){
    logErr("Failed to validate the Socks5 connection");
    return 0;
  }
  
  return 1;
}


/* socks5Handshake is passed a socket connected to a Socks5 proxy, over which it
 * engages in the Socks5 handshake. The proxy must support Socks5, currently we
 * are not supporting authentication so the proxy must not require it. 
 *
 * Reference: https://www.ietf.org/rfc/rfc1928.txt 
 *
 * Returns 1 on success, 0 on error.
 */ 
static int socks5Handshake(int socket)
{ 
  int  responseBc = 2;
  int  sendBc     = 3;
  char proxyResponse[responseBc]; 
  
  /* Ensure the socket is valid */
  if( socket == -1 ){
    logErr("Socket passed to socks5Handshake is invalid");
    return 0;
  }
  
  /* Send the initial three bytes of the handshake to the Socks5 Proxy */
  if( send(socket, "\005\001\000", sendBc, 0) != sendBc ){
    logErr("Failed to send first byte sequence of Socks5 handshake");
    return 0; 
  } 
  
  /* Receive the initial response from the Socks5 Proxy */
  if( recv(socket, proxyResponse, responseBc, 0) != responseBc ){
    logErr("Failed to receive first response during Socks5 handshake");
    return 0;
  }
  
  /* Ensure that the proxy supports Socks5 */
  if( proxyResponse[0] != 5 ){
    logErr("Socks proxy doesn't support Socks5");
    return 0;
  }
  
  /* Ensure that the proxy supports a lack of authentication */
  if( proxyResponse[1] != 0 ){
    logErr("Socks proxy doesn't support a lack of authentication");
    return 0;
  }
  
  return 1; 
}

/* socks5UrlCon makes a request to the Socks5 proxy to establish a connection 
 * to the URL pointed to by url, which is bc bytes long, on the port denoted 
 * by port. Socket must already be connected to the Socks5 proxy, and must 
 * have already engaged in the Socks5 handshake.  
 *
 * Reference: https://www.ietf.org/rfc/rfc1928.txt
 *
 * Client Request Format:
 *
 * +----+-----+-------+------+----------+----------+
 * |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
 * +----+-----+-------+------+----------+----------+
 * | 1  |  1  | X'00' |  1   |[bc1]+Var |    2     |
 * +----+-----+-------+------+----------+----------+
 *  
 * Returns 1 on success, 0 on error.
 */
static int socks5UrlCon(int socket, char *url, uint8_t bc, uint16_t port)
{
  uint8_t      maxBc = 255;                          // (2^8 - 1) = 255  
  unsigned int fixedSocksBc = 1 + 1 + 1 + 1 + 1 + 2; // See diagram 
  unsigned int actualBc = maxBc + fixedSocksBc;
  char         socksRequest[fixedSocksBc + maxBc];    
  
  /* Basic error checking */
  if( url == NULL || bc == 0 ){
    logErr("Something was NULL that shouldn't have been"); 
    return 0; 
  }
  
  /* Ensure the socket is valid */
  if( socket == -1 ){
    logErr("Socket passed to socks5UrlCon is not valid");
    return 0;
  }
  
  /* format the destination port in network order in accordance with RFC */
  port = htons(port);
  
  /* with || denoting concatenation and [x] denoting of x bytes: 
  *
  *  socks version five [1] || connect [1] || RSV is NULL [1] || 
  *  url is url not an IP addr [1] || prepend url with bytesize as octet [1] ||
  *  url [var bytes] || destination port in network octet order [2]    
  */
  memcpy(&socksRequest[0], "\005\001\000\003", 4);
  memcpy(&socksRequest[4], &bc, 1);
  memcpy(&socksRequest[5], url, bc);
  memcpy(&socksRequest[5 + bc], &port, 2);
  
  /* Initialize the Socks 5 Connection */  
  if( send(socket, socksRequest, actualBc, 0) != actualBc ){
    logErr("Failed to transmit URL connection request to Socks5 Proxy");
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
static int socks5ValidateResponse(int socket)
{
  uint8_t domainBc;
  uint8_t ipv4Octets   = 4;
  uint8_t ipv6Octets    = 16; 
  
  uint8_t uint8Max = 255;                   //(2^8 - 1) = 255
  uint8_t fixedBc  = 1 + 1 + 1 + 1 + 1 + 2; //See Diagram, 1 fixed is actually var 
  
  /* For holding responses from the Socks5 Proxy. The maximum bytes that will 
   * be written to it are in the case that the Socks5 Proxy is on a domain, 
   * in which case BND.ADDR consists of an initial octect encoding the number 
   * of subsequent octets. Since an octet can only encode up to 255, this means
   * BND.ADDR can only be up to 255 + 1 bytes. The other bytes are fixed, see 
   * the diagram. In the case that the proxy is not on a domain, BND.ADDR will 
   * either be 4 bytes in the case it is on an IPv4 address, or 16 in the case
   * that it is on an IPv6 address.    
   */
  char proxyResponse[uint8Max + fixedBc]; 
  
  /* Make sure that the socket is valid */
  if(socket == -1){
    logErr("Socket passed to socks5ValidateResponse is invalid"); 
    return 0; 
  }
  
  /* PROXY RESPONSE FORMAT DIAGRAM
  * 
  * +----+-----+-------+------+----------+----------+
  * |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
  * +----+-----+-------+------+----------+----------+
  * | 1  |  1  | X'00' |  1   | [~bc1]Var|    2     |
  * +----+-----+-------+------+----------+----------+
  */
  if( recv(socket, proxyResponse, 4, 0) != 4 ){
    logErr("Failed to receive validation from Socks5 proxy");
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
   * if ATYP is 3, BND.ADDR is a domain name of variable octets 
   * if ATYP is 4, BND.ADDR is an IPv6 address encoded as 16 octets. 
   *
   * We don't really care about this, only that success was had, however,
   * we do want to make sure to clear the socket buffer 
   */ 
  switch(proxyResponse[3]){
    case 1: //Socks proxy is on ipv4, need to clear 4 + 2 octets 
      if( recv(socket, proxyResponse, ipv4Octets + 2, 0) != ipv4Octets + 2 ){
        logErr("Failed to receive validation response from Socks5 Proxy");
        return 0; 
      }
      break;
    case 3: //Socks proxy is on a domain, need to clear variable octets + 2
      if( recv(socket, proxyResponse, 1, 0) != 1 ){ //First octet encodes count
        logErr("Failed to get byte encoding domain octet count");
        return 0;
      }
      domainBc = proxyResponse[0]; 
      if( recv(socket, proxyResponse, domainBc + 2, 0) != domainBc + 2 ){
        logErr("Failed to receive validation from Socks5 Proxy");
        return 0;
      }
      break;
    case 4: //Socks proxy is on ipv6, need to clear 16 + 2 octets
      if( recv(socket, proxyResponse, ipv6Octets + 2, 0) != ipv6Octets + 2 ){
        logErr("Failed to receive validation from Socks5 Proxy");
        return 0; 
      }
      break;
    default: //Response was not valid
      logErr("Something unexpected happened with the Socks Proxy response");
      return 0; 
  }
  return 1; 
}
