#include <stdio.h>
#include <stdlib.h>
#include <sched.h> 
#include <errno.h>
#include <sys/syscall.h>  
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mount.h>

#include "isolFs.h" 


int isolFs(int initNs)
{
  if( initNs != INIT_FSNS && initNs != NO_INIT_FSNS ){
    printf("Error: Invalid argument passed to isolFs\n");
    return 0; 
  } 
  
  /* Initialize the namespace mount isolation if the argument is INIT_FSNS */
  if(initNs == INIT_FSNS && unshare(CLONE_NEWNS) ){
    printf("Failed to unshare the filesystem\n");
    return 0; 
  } 
  
  /* Recursively remount rootfs as private, this gets around the problem that
   * systemD introduced by making everything mounted as shared 
   */
  if( mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) ){
    printf("Failed to recursively remount / as private\n");
    return 0; 
  }
   
   /* Ensure that the sandbox directory exists */
  if( mkdir("gui_sandbox", S_IRUSR | S_IWUSR | S_IXUSR) && errno != EEXIST ){
    printf("Failed to make or utilize the sandbox directory for GUI\n");
    return 0;
  } 
  
   /* Create the mount point for the new root */ 
   if( mount(NULL, "gui_sandbox", "ramfs", MS_NOEXEC, "rw,noexec") ){ 
    printf("sandbox directory appears to be missing\n");
    return 0; 
  }
  
  if( chdir("gui_sandbox") ){
    printf("Failed to cd to sandbox dir, is there a nondir named 'sandbox' at pwd?\n");
    return 0;
  }
  
  
  /* Create the directory for oldroot if it doesn't already exist */ 
  rmdir("oldroot");
  unlink("oldroot"); 
  if( mkdir("oldroot",  S_IRUSR |  S_IWUSR | S_IXUSR) ){ 
    printf("Failed to make oldroot directory, does such a directory" 
           "already exist with files in it? It should be deleted.");
    return 0;
  }
  
  
  /* Make the current directory new root and pivot old root to oldroot */ 
  if( syscall(SYS_pivot_root, ".", "oldroot") ){ 
    printf("Failed to switch root for sandbox");
    rmdir("oldroot");
    return 0; 
  }
  
  
  /* Change to the new root directory, which is already where we are */
  if( chdir("/") ){
    printf("Failed to chdir to new root for sandbox");
    return 0;
  }
  
  /* Unmount the old root directory and every directory under it, such that the
   * process has no more access to them.  
   */
  if( umount2("oldroot", MNT_DETACH) ){
    printf("Failed to unmount old root from sandbox");
    fflush(stdout); 
    return 0; 
  }
  
  /* The old root directory no longer has anything mounted to it, so remove it
   */
   rmdir("oldroot");
  
  return 1;
}
