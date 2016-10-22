#include <stdlib.h> 
#include <unistd.h>
#include <seccomp.h>
#include <sched.h>
#include <errno.h>
#include <stdio.h> 
#include <string.h>


#include "initIsolWin.h"


extern "C"{
  #include "isolFs.h" 
  #include "logger.h"
}

static int forkXephyr(void);
static int seccompWl(void);
static void isolXephyr(const char *xephyrCmd[], const char *xephyrEnv[]);

static int setDisplayName(char *dOut, int dOutBc, char *lockStr , int lockStrBc);


/* initIsolWin spawns a window that is isolated from the host's windowing 
 * system. In this implementation we are using Xephyr to do so. 
 *
 * Returns 1 on success, 0 on error.
 */
int initIsolWin(void)
{
  if( !forkXephyr() ){
    logErr("Failed to isolate the GUI");
    return 0; 
  }
  
  return 1; 
}

//todo grab Xephyr location from settings file

/* forkXephyr forks the current process and begins the Xephyr isolation from 
 * the child, the parent sets the DISPLAY environment variable to the available 
 * display number that is generated for X11 and then returns.
 *
 * Returns 1 on success, 0 on error. 
 */
static int forkXephyr(void) 
{
  char xDisplayName[100]; 
  char lockStr[100]; 
  
  /* Get an available valid xDisplayName */
  if( !setDisplayName(xDisplayName, 100, lockStr, 100) ){
    logErr("Failed to set a display name for GUI isolation");
    return 0; 
  }
  
  /* Xephyr flags + environment variables */
  const char *xephyrCmd[] = {"Xephyr", "-ac", "-br", "-noreset", "-title", "App", "-nolisten", "tcp", "-resizeable", "-screen", "800X600", (const char*)xDisplayName, NULL };
  const char *xephyrEnv[] = {"DISPLAY=:0", NULL};
  
  /* Fork and start the isolation of Xephyr from the child, set the DISPLAY 
   * environment variable from the parent to that of the Xephyr window the 
   * the child spawns
   */ 
  switch( fork() ){
    case -1:{
      logErr("Failed to fork off Xephyr");
      return 0;
    }
    
    case 0:{
      isolXephyr(xephyrCmd, xephyrEnv); /* This never returns */
      logErr("Failed to isolate Xephyr");
      return 0;
    }
    
    default:{
      if( setenv("DISPLAY", xDisplayName, 1) ){
        logErr("Failed to set display environment var to xephyr display #");
        return 0;
      }
    }
  }
  
  return 1; 
}

/* isolXephyr goes about actually bringing up the isolated Xephyr display. 
 * The Xephyr process is itself isolated from the file system, note that this
 * actually happens /after/ it is execve such that it has access to the file
 * system in order to bring in the dynamically linked libraries it requires.
 *
 * The mount namespace is initialized prior to a fork, such that both the 
 * parent and the child fork are in it, Xephyr is execved in the child after
 * isolating it from kernel syscalls it doesn't need with SECCOMP, then after a 
 * one second delay the parent isolates entirely from the file system such that 
 * Xephyr has no access to it other than through its already open file 
 * descriptors. I've not found a way to make this event driven.
 *
 * This function does not return, on error it will fail with a log message,
 * and the Xephyr Window may not launch, or in the event it does it may not
 * be isolated from the file system, though hopefully this will never happen. 
 */
static void isolXephyr(const char *xephyrCmd[], const char *xephyrEnv[])
{
  /* Initialize a new mount namespace for Xephyr, we do this here so that after
   * we execve to Xephyr we can then modify this same mount namespace to remove
   * access to the file system. This is done after we execve so that dynamically
   * linked libraries and such can be accessed ahead of time.    
   */ 
  if( unshare(CLONE_NEWNS) ){
    logErr("Failed to unshare the filesystem");
    exit(-1);  
  } 
  
  /* Now we fork again so that we can execve Xephyr and still modify the 
   * previously created mount namespace
   */
  switch( fork() ){
    /* Failed to fork */
    case -1:{
      logErr("Failed to fork for Xephyr");
      exit(-1);
    } 
    
    /* The child initializes the xephyr SECCOMP profile and execves xephyr */ 
    case 0:{
     /* Initialize the Xephyr SECCOMP whitelist */
      if( !seccompWl() ){
        logErr("Failed to initialize SECCOMP for isolated window\n");
        exit(-1);  
      }
     
      if( execve("/usr/bin/Xephyr", (char**)xephyrCmd, (char**)xephyrEnv) == -1 ){
        logErr("Failed to execve Xephyr");
        exit(-1);
      }
    }
    
    /* The parent removes Xephyrs access to the filesystem */ 
    default:{
      /* This is the best method I've found for determining when Xephyr is ready 
       * here, polling for filesystem changes isn't accurate enough, polling for
       * ability to connect to the display causes problems in initWm.cxx when it
       * tries to connect. TODO find a way to make this not disgusting. 
       */
      sleep(1); 
      
      if( !isolFs("gui_sandbox", NO_INIT_FSNS) ){
        logErr("Failed to isolate Xephyr from the filesystem");
        exit(-1); 
      }
      exit(0);
    }
  }
  
  /* We should never actually make it here */
  logErr("A part of code that shouldn't ever be reached was reached anyway");
  exit(-1); 
}


/* setDisplayName writes a valid x11 display name to the buffer pointed to by
 * dOut. This will be a number 1..65534, prefixed with :, represented as an ASCII 
 * character string, that is not currently in use, and which is valid for x11 
 * when using unix domain sockets (ie: -nolisten tcp).  
 *
 * The path to the x11 lock file will be written to the buffer pointed to by 
 * lockStr, this is in the form of "/tmp/.X#-lock", where # is a variable for 
 * the x11 display number. 
 *
 * Note that there will be a slight TOCTOU window between setDisplayName 
 * determining that the output display name is not currently in use, and 
 * actually using the output display name by the caller function, however in
 * practice this should not matter, and checking will prevent most errors. 
 *
 * Returns 1 on success, 0 on error.
 */  
static int setDisplayName( char *dOut, int dOutBc, char *lockStr, int lockStrBc)
{
  int      checker;  
  uint16_t displayName = 0; 
  
  /* Basic error checking */ 
  if( dOut == NULL || dOutBc == 0 || lockStr == NULL || lockStrBc == 0 ){
    logErr("Something was NULL that shouldn't have been");
    return 0; 
  }
  
  /* Keep incrementing the displayName number, check the number to see if x11 
   * is already using a display with this name, if it is try again, if it is
   * not we are done and the display name in the format :displayName has been
   * written to the output buffer
   */ 
  do{
    displayName++;
    
    if( displayName == 65535 ){
      logErr("Tried an absurd number of display names and none worked");
      return 0;
    }
    
    /* Write the current display number to the output buffer with : prepended to it */ 
    checker = snprintf(dOut, dOutBc, ":%u", displayName);
    if( checker >= dOutBc || checker < 0 ){
      logErr("Failed to snlogErr the display name integer as an ASCII string");
      return 0; 
    }
    
    /* Write the path to the ambiguously existing lock file for this display */ 
    checker = snprintf(lockStr, lockStrBc, "/tmp/.X%u-lock", displayName);
    if( checker >= lockStrBc || checker < 0 ){
      logErr("Failed to snlogErr the path to the x11 lock file for exist check");
      return 0; 
    } 
    
    /* Make sure that the x11 lock file for this display doesn't already exist */
    errno   = 0; 
    checker = access(lockStr, F_OK);
  }while( errno != ENOENT );
  
  return 1; 
}


/* seccompWl applies a SECCOMP whitelisting filter to the forked off Xephyr 
 * process such that attempts to use syscalls / parameters that haven't been 
 * whitelisted results in an immediate segfault of the Xephyr process.
 *
 *  //TODO more detail here like the others! 
 *
 * Returns 1 on success, 0 on error. 
 */ 
static int seccompWl(void)
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

  /********************************XEPHYR NEEDS********************************/ 

  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(select), 1,
                          SCMP_CMP( 0 , SCMP_CMP_EQ , 512));
  
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(wait4), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(mmap), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(getrlimit), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(read), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(write), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(open), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(close), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(stat), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(fstat), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(lstat), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(poll), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(lseek), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(mprotect), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(munmap), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(brk), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(rt_sigaction), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(rt_sigreturn), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(rt_sigprocmask), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(writev), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(access), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(pipe), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(shmget), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(shmat), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(shmctl), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(socket), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(connect), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(recvfrom), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(recvmsg), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(bind), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(listen), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(getsockname), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(getpeername), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(getsockopt), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(clone), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(execve), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(uname), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(shmdt), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(fcntl), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(link), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(unlink), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(fchmod), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(umask), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(sysinfo), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(geteuid), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(getppid), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(getpgrp), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(statfs), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(arch_prctl), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(futex), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(set_tid_address), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(clock_getres), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(set_robust_list), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(dup2), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(getpid), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(getcwd), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(chdir), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(getuid), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(getgid), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(setuid), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(setgid), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(getegid), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(exit_group), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(prctl), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(nanosleep), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(kill), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(readlink), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(fadvise64), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(fstatfs), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(getdents), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(accept), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(setitimer), 0); 

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
