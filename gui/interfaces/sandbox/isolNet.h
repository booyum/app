#pragma once

/* isolNet shall implement network isolation such that the calling process loses
 * its ability to route traffic. 
 *
 * Implementations of this will vary significantly, the Linux implementation is
 * using network namespaces to completely isolate the process from all networking
 * devices, including from their MAC addresses.
 */
int isolNet(void); 
