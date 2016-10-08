#pragma once

/* isolFs shall implement filesystem isolation such that the calling process 
 * will be isolated from the filesystem 
 * 
 * TODO explain to what extent 
 *
 * Returns 1 on success, 0 on error.
 */  

enum{ NO_INIT_FSNS = 0, INIT_FSNS = 1 }; 

int isolFs(int initNs);
