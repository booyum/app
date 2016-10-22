#define _GNU_SOURCE

#include <sched.h>

#include "isolProc.h"
#include "logger.h"
#include "security.h"

void isolProc(int (*execFunct)(void *))
{
  if( execFunct == NULL ){
    logErr("Isolation of process failed, something incorrectly was NULL");
    exit(-1);
  }

  if( secClone(execFunct, CLONE_NEWPID) == -1 ){
    logErr("Isolation of process failed, secClone had an error");
    exit(-1);
  }
  
  exit(0);
}
