#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <errno.h>
#include <sys/stat.h>
#include <seccomp.h>


#include "initIsolWin.h" 
#include "initWm.h"
#include "initGui.h"
#include "contPortCon.h" 

extern "C"{
  #include "logger.h"
  #include "security.h"
  #include "isolNet.h" 
  #include "isolName.h"
  #include "isolIpc.h" 
}

/* Simple bootstrapper to initialize the window manager and GUI */ 

/* Enums for the positions of argv */
enum{ CONT_PORT_TOKEN = 1 }; 

/* For extern */ 
static int gControlSocket = -1; 

int main(int argc, char *argv[])
{
  /* We should be passed two arguments when main is called, the first is 
   * simply the binary name by convention, the second is a 32 byte random
   * token for authenticating to the control port of the primary application
   */
  if( argc != 2 ){
    logErr("Wrong number of arguments passed to the GUI main");
    return -1; 
  }
  
  /* Prevent unexpected forensic traces by disabling core dumps and paging */
  if( !mitigateForensicTraces() ){
    logErr("Failed to disable core dumps / swapping to counter disk forensics");
    return -1; 
  }
  
  
  /* Ensure that the sandbox directory exists */
  if( mkdir("gui_sandbox", S_IRUSR | S_IWUSR | S_IXUSR) && errno != EEXIST ){
    logErr("Failed to make or utilize the sandbox directory for GUI");
    return 0;
  } 
  
  /* Initialize the logger, we will log to the file 'log' in the gui_sandbox */
  if( !initLogFile("gui_sandbox/log") ){
    logErr("Failed to initialize log file");
    return 0; 
  }
  
  /* The isolated window, window manager, and GUI, do not need networking */ 
  if( !isolNet(SIMPLE) ){
    logErr("Failed to isolate from the network"); 
    return -1; 
  }
  
  /* We don't need access to any system names either */ 
  if( !isolName() ){
    logErr("Failed to isolate from names");
    return -1;
  }
  
  /* Bring up the isolated Window */
  if( !initIsolWin() ){
    logErr("Failed to bring up an isolated window");
    return -1; 
  }
  
  /* We isolate from IPC now rather than earlier so that the isolated window 
   * is not prevented from using MIT-SHM, without this it is extremely glitch.
   */ 
  if( !isolIpc() ){
    logErr("Failed to isolate from IPC");
    return -1; 
  }
  
  /* Make the control port connection */
  gControlSocket = initContPortCon( argv[CONT_PORT_TOKEN] );
  if( gControlSocket == - 1){
    logErr("Failed to get control socket");
    return -1; 
  } 
  
  /* Initialize the window manager and GUI */ 
  if( !initWm(&initGui) ){
    logErr("Failed to initialize the GUI");
    return -1; 
  }
  
  return 0; /* initWm should never return */ 
}




/* This SECCOMP profile is currently being used for both the window manager 
 * and the GUI toolkit, however it can likely be fragmented into two independent
 * profiles, TODO
 */ 
int isolKern(void)
{
  scmp_filter_ctx filter;
  int             ret = 0; 

  /* Initialize SECCOMP filter such that non-whitelisted syscalls segfault */
  filter = seccomp_init(SCMP_ACT_TRAP);
  if( filter == NULL ){
    logErr("Failed to initialize a seccomp filter");
    return 0;
  }

  /*********************SYSCALL WHITELIST SPECIFICATION************************/

  /* The code below defines allowed syscalls + the arguments allowed to them */ 

  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(select), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(poll), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(stat), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(recvmsg), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(read), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(fstat), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(writev), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(write), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(open), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(close), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(mmap), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(mprotect), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(munmap), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(brk), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(rt_sigaction), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(rt_sigprocmask), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(access), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(mremap), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(socket), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(connect), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(setsockopt), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(recvfrom), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(getpeername), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(clone), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(execve), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(uname), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(fcntl), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(getdents), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(mkdir), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(readlink), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(getrlimit), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(sysinfo), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(getuid), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(getgid), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(geteuid), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(getegid), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(fstatfs), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(arch_prctl), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(futex), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(set_tid_address), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(fadvise64), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(set_robust_list), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(exit_group), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(lseek), 0);
  
  /**************************COMPLETE INITIALIZATION***************************/ 

  /* Make sure that all of the SECCOMP rules were correctly added to filter */
  if( ret != 0 ){
    logErr("Failed to initialize seccomp filter");
    seccomp_release(filter);
    return 0;
  }

  /* Load the SECCOMP filter into the kernel */
  if( seccomp_load(filter) ){
    logErr("Failed to load the seccomp filter into the kernel");
    seccomp_release(filter); 
    return 0; 
  }

  /* Free the memory associated with the SECCOMP filter, it has been loaded */ 
  seccomp_release(filter);

  return 1;
}





