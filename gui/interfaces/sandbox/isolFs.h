#pragma once

/* isolFs shall implement filesystem isolation such that the calling process 
 * will be entirely contained to a directory named 'sandbox' located in the 
 * directory from which its binary was executed. If the 'sandbox' directory
 * does not currently exist, an attempt will be made to create it.
 *
 * On all Unix like implementations, the sandbox directory shall become the new
 * root directory of the process.
 *
 * Returns 1 on success, 0 on error.
 */  
int isolFs(void);
