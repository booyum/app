#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <stdlib.h>
#include <seccomp.h>
#include <sys/mman.h>
#include <sys/types.h>     
#include <sys/socket.h>

#include "isolProc.h"
#include "isolFs.h"
#include "isolName.h"
#include "isolIpc.h" 
#include "isolNet.h"
#include "isolGui.h"

#include "security.h"
#include "logger.h"
#include "prng.h" 
#include "controller.h" 


static int bootstrap(void); 
static int initIsolation();
static int prepSandbox(char *path);
static int isolKern(void);

int main()
{
  if( !bootstrap() ){
    logErr("Failed to bootstrap the application");
    return -1;
  }
  
  isolProc(&initIsolation);
  return 0; 
}

/* Bootstrap begins the initialization of the application by taking measures to
 * prevent unexpected forensic traces from being left on the hard drive, 
 * preparing the sandbox directory, ininitializing the logger, initializing 
 * the PRNG, initializing the control port, and starting the GUI.
 *
 * Returns 1 on success, 0 on error. 
 */
static int bootstrap(void)
{
  /* Prevent unexpected forensic traces by disabling core dumps and paging */
  if( !mitigateForensicTraces() ){
    logErr("Failed to disable core dumps / swapping to counter disk forensics");
    return 0; 
  }
  
  /* Prepare the sandbox directory */
  if( !prepSandbox("sandbox") ){
    logErr("Failed to prepare the sandbox directory");
    return 0; 
  }
  
  /* Initialize the logger */
  if( !initLogFile("sandbox/log") ){
    logErr("Failed to initialize log file");
    return 0; 
  }
  
  /* Initialize the PRNG (note we must NOT be isolated into sandbox dir) */ 
  if( !initializePrng() ){
    logErr("Failed to initialize the PRNG");
    return 0;
  }
  
  /* Initialize the controller, PRNG must be initialized */
  if( !initializeController() ){
    logErr("Failed to initialize the control port interface");
    return 0; 
  }
  
  /* Bring up the GUI, it is passed the control token and token byte count */
  if( !isolGui( getCpToken() ) ){
    logErr("Failed to isolate the GUI");
    return 0; 
  }
  
  return 1; 
}


/* initIsolation goes through the process of isolating the application from 
 * the filesystem (into the sandbox directory), isolating from the host and 
 * domain names, isolating from interprocess communication, isolating from 
 * the network hardware, and isolating from kernel syscalls that are not 
 * required.
 */ 
static int initIsolation()
{
/* Note that isolNet is called after all functions other than isolKern so that
 * the spawned redirector process is also isolated, however it uses its own 
 * kernel isolation and therefore isolKern is called after it. 
 */ 

  /* Isolate the process to the sandbox directory (new root on Unix) */ 
  if( !isolFs("sandbox", INIT_FSNS) ){
    logErr("Failed to isolate the filesystem");
    return 0; 
  }
  
  /* Isolate the process from system names */
  if( !isolName() ){
    logErr("Failed to isolate from system names");
    return 0;
  }
  
  /* Isolate the process from IPC */
  if( !isolIpc() ){
    logErr("Failed to isolate from IPC");
    return 0; 
  }
  
  /* Isolate the process from the network */
  if( !isolNet(REDIRECT) ){
    logErr("Failed to isolate the network");
    return 0;
  }
  
  /* Isolate the process from kernel functionality */ 
/*  if( !isolKern() ){*/
/*    logErr("Failed to isolate kernel functionality");*/
/*    return 0; */
/*  }*/
  
  return manageControlPort(); 
}

/* prepSandbox prepares the sandbox directory by creating it in the current 
 * directory of the process if it doesn't already exist. 
 *
 * Returns 1 on success, 0 on error.
 */
static int prepSandbox(char *path)
{
  /* Basic Error Checking */
  if( path == NULL ){
    logErr("Something was NULL that shouldn't have been");
    return 0;
  }
  
    /* Create the sandbox directory if it does not already exist. */ 
  switch( mkdir(path, S_IRUSR | S_IWUSR | S_IXUSR) ){
    /* The directory didn't exist and was successfully created */
    case 0:{
      logMsg("sandbox directory didn't already exist, created sandbox directory"); 
      break;
    }
    /* The directory either existed, or we failed to create it */
    default:{
      /* The directory existed, we will use it and all is fine */
      if( errno == EEXIST ){
        logMsg("sandbox directory seems to exist, attempting to use it");
        break;
      }
      /* The directory didn't exist and we failed to create it */ 
      logErr("Failed to create sandbox directory, and it doesn't already exist");
      return 0;
    }
  }
  
  return 1;
}






/* isolKern implements kernel syscall isolation such that attempts to use 
 * syscalls that haven't been whitelisted, or whitelisted syscalls with 
 * arguments that haven't been whitelisted, results in an immediate segfault.
 *
 * Note that we prevent the process from obtaining any sockets other than 
 * Unix Domain Sockets, which should prevent any proxy bypass attacks.
 *
 * Returns 1 on success, 0 on error.
 */ 
static int isolKern(void)
{
  scmp_filter_ctx filter;
  int             ret = 0; 

  /* Initialize SECCOMP filter such that non-whitelisted syscalls segfault */
  filter = seccomp_init(SCMP_ACT_KILL);
  if( filter == NULL ){
    logErr("Failed to initialize a seccomp filter");
    return 0;
  }

  /*********************SYSCALL WHITELIST SPECIFICATION************************/

  /* The code below defines allowed syscalls + the arguments allowed to them */ 


  /****************************NETWORKING SYSCALLS*****************************/ 

  /* Only allow sendto with NULL for dest_addr, 0 for addrlen. This prevents
   * this syscall from being used directly to transmit UDP traffic, hardening
   * from proxy bypass attacks. 
   */  
  ret |= seccomp_rule_add( filter, SCMP_ACT_ALLOW, 
                           SCMP_SYS(sendto), 2,  
                           SCMP_CMP( 4 , SCMP_CMP_EQ , 0), 
                           SCMP_CMP( 5 , SCMP_CMP_EQ , 0)
                         );

  /* Only allow recvfrom with NULL for src_addr, 0 for addrlen. We don't plan
   * to support receiving UDP traffic, and this may help in preventing some 
   * attacks on anonymity. 
   */   
  ret |= seccomp_rule_add( filter, SCMP_ACT_ALLOW, 
                           SCMP_SYS(recvfrom), 2,
                           SCMP_CMP( 4 , SCMP_CMP_EQ , 0), 
                           SCMP_CMP( 5 , SCMP_CMP_EQ , 0)
                         );

  /* Only allow the socket syscall with AF_UNIX domain (unix sockets),
   * SOCK_STREAM for type, and the default protocol (0). In doing this,
   * we should prevent proxy bypasses. 
   */ 
  ret |= seccomp_rule_add( filter, SCMP_ACT_ALLOW, 
                           SCMP_SYS(socket), 3, 
                           SCMP_CMP( 0 , SCMP_CMP_EQ , AF_UNIX),
                           SCMP_CMP( 1 , SCMP_CMP_EQ , SOCK_STREAM),
                           SCMP_CMP( 2 , SCMP_CMP_EQ , 0)
                         );

  /* Poll is used for managing the sockets */
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(poll), 0);

  /* For now generically whitelisting connect, maybe restrict more later */
  ret |= seccomp_rule_add( filter, SCMP_ACT_ALLOW, SCMP_SYS(connect), 0);


  /*******************************MEMORY SYSCALLS******************************/ 

  /* Allow mprotect unless it is trying to set memory as executable */ 
  ret |= seccomp_rule_add( filter, SCMP_ACT_ALLOW, 
                           SCMP_SYS(mprotect), 1,
                           SCMP_CMP( 2 , SCMP_CMP_NE , PROT_EXEC)
                         );

  /* secAlloc and secFree require these */ 
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(mmap), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(munmap), 0);


  /********************************OTHER SYSCALLS******************************/ 

  /* At least the logger requires these */
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(flock), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(write), 0);
  
  /* Required to exit */ 
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(exit_group), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(exit), 0);

  /* Not exactly sure why I need but think they are required TODO */ 
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(close), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(open), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(read), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(fstat), 0);

  /**************************COMPLETE INITIALIZATION***************************/ 

  /* Make sure that all of the SECCOMP rules were correctly added to filter */
  if( ret != 0 ){
    logErr("Failed to initialize seccomp filter");
    seccomp_release(filter);
    return 1;
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






