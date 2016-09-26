#pragma once
#include <stdint.h>

struct routerObj;

typedef struct routerClassMethods{
  int (*socks5Relay)(struct routerObj *this, char *addr, uint8_t addrBytesize, uint16_t port);
  int (*receive)(struct routerObj *this, void *buff, uint32_t bytesRequested);
  int (*transmit)(struct routerObj *this, void *buff, uint32_t bytesToSend);
  int (*transmitBytesize)(struct routerObj *this, uint32_t bytesize);
  uint32_t (*getIncomingBytesize)(struct routerObj *this);
  int (*torConnect)(struct routerObj *this);
  int (*ipv4Listen)(struct routerObj *this, char *addr, uint16_t port);
  int  (*getConnection)(struct routerObj *this);
  int  (*setSocket)(struct routerObj *this, int socket);
  int (*destroyRouter)(struct routerObj **thisPointer); 
  int (*reinitialize)(struct routerObj *this); 
}routerClassMethods; 

/* Public Object Prototype */
typedef struct routerObj{
  struct routerClassMethods *methods;  
}routerObj;


routerObj* newRouter(void);

