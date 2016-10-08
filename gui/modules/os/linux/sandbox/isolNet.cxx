#include <stdio.h>
#include <sched.h>
#include "isolNet.h"

/* Simply wrap unshare(CLONE_NEWNET) to completely isolate the process from 
 * all networking interfaces
 */ 
int isolNet(void)
{
  if( unshare(CLONE_NEWNET) ){
    printf("Error: unshare clone_newnet failed\n");
    return 0;
  }
  return 1; 
}
