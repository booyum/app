#pragma once

uint32_t getIncomingBc(int socket);
int sendOutgoingBc(int socket, uint32_t outgoingBc);
int ipv4Listen(const char *addr, uint16_t port);
int udsConnect(char *udsPath, unsigned int bc);
int udsListen(char *path, int bc);
