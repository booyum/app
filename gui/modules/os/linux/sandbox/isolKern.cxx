#include <seccomp.h>
#include <stdio.h>

#include "isolKern.h"

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
    printf("Failed to initialize a seccomp filter");
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
    printf("Failed to initialize seccomp filter");
    seccomp_release(filter);
    return 0;
  }

  /* Load the SECCOMP filter into the kernel */
  if( seccomp_load(filter) ){
    printf("Failed to load the seccomp filter into the kernel");
    seccomp_release(filter); 
    return 0; 
  }

  /* Free the memory associated with the SECCOMP filter, it has been loaded */ 
  seccomp_release(filter);

  return 1;
}
