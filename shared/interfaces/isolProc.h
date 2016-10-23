#pragma once

/* isolProc shall implement process isolation such that the calling process has 
 * reduced access to the other processes running on the system. After a call to 
 * isolProc returns, execution will resume at the function pointed to by 
 * execFunct.
 *
 * On Linux this is implemented via clone into a PID namespace isolated child 
 * process that starts execution at execFunct, with the calling process being
 * immediately terminated after the child starts execution. 
 *
 * isolProc does not return.  
 */

void isolProc(int (*execFunct)(void *));
