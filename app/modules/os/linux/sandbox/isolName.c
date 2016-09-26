#define _GNU_SOURCE

#include <sched.h>
#include <unistd.h>

#include "isolName.h"

 
 /* isolName isolates from the host and domain names, spoofing them to 
  * "isolated"
  */ 
int isolName(void)
{
  return( !unshare(CLONE_NEWUTS)        && 
          !sethostname("isolated", 8)   && 
          !setdomainname("isolated", 8) 
        ); 
}
