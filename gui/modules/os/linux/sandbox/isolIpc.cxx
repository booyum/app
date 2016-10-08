#include <sched.h>

#include "isolIpc.h"

/* isolIpc is simply a wrapper around unshare(CLONE_NEWIPC), 
 * returns 1 on success, 0 on error. 
 */
int isolIpc(void)
{
  return !unshare(CLONE_NEWIPC);
}
