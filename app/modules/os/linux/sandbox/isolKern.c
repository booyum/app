#include <stdlib.h>
#include <seccomp.h>
#include <sys/mman.h>
#include <sys/types.h>     
#include <sys/socket.h>

#include "isolKern.h"
#include "logger.h" 


/* isolKern implements kernel syscall isolation such that attempts to use 
 * syscalls that haven't been whitelisted, or whitelisted syscalls with 
 * arguments that haven't been whitelisted, results in an immediate segfault.
 *
 * Note that we prevent the process from obtaining any sockets other than 
 * Unix Domain Sockets, which should prevent any proxy bypass attacks.
 *
 * Returns 1 on success, 0 on error.
 */ 
int isolKern(void)
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

