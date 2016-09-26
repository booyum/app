#pragma once

/* isolKern shall implement kernel syscall isolation such that the process has
 * restricted access to the kernel, when support is provided by the operating 
 * system, this shall include preventing connections that bypass Tor.
 *
 * On the Linux implementation, SECCOMP syscall filtering is utilized for the 
 * implementation of isolKern, and Tor bypasses are prevented by only allowing
 * socket() to return unix domain sockets.  
 */

int isolKern(void); 
