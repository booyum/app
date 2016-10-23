#pragma once

enum{ REDIRECT = 1, SIMPLE = 0 };

/* isolNet shall implement network isolation such that the calling process loses
 * its ability to route traffic other than over connections to the Tor SocksPort.
 *
 * Implementations of this will vary significantly, the Linux implementation is
 * using network namespaces to completely isolate the process from all networking
 * devices, including from their MAC addresses, with all connections to the Tor
 * SocksPort going through a Unix Domain Socket connection.
 */
int isolNet(int initRedirector);
