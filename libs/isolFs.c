#define _GNU_SOURCE

#include <sched.h> 
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <sys/mount.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>  
#include <linux/limits.h>

#include <stdio.h>

#include "isolFs.h"
#include "security.h"
#include "logger.h"


/* isolFs creates a mount point for path such that it maps to itself.
 * This allows for modifications to the mount point to transparently map to the
 * actual directory.
 *
 * After path is mounted to itself, creates a new temporary directory 
 * "oldroot" in path, then pivots root such that path is the new root
 * for the process, and "oldroot" is the old root. 
 *
 * After this, change directory to the new root, then unmount the old root and
 * everything below it to isolate the process from the old filesystem. 
 *
 * After this, clean up by deleting the oldroot directory, which is no longer 
 * needed.
 *
 * NOTE:  Currently only mapping in the sandbox directory and anything below it, 
 *        other directories may need mapped in as other code progresses. 
 *
 * Returns 0 on error, 1 on success.
 */
 
int isolFs(char *path, int initNs)
{ 
  /* Make sure that initNs is a valid argument */
  if( initNs != INIT_FSNS && initNs != NO_INIT_FSNS ){
    logErr("Invalid argument passed to isolFs");
    return 0; 
  } 
  
  /* Initialize the namespace mount isolation, if the argument is INIT_FSNS */
  if(initNs == INIT_FSNS && unshare(CLONE_NEWNS) ){
    logErr("Failed to unshare the filesystem");
    return 0; 
  } 
  
  /* Recursively remount rootfs as private, this gets around the problem that
   * systemD introduced by making everything mounted as shared 
   */
  if( mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) ){
    logErr("Failed to recursively remount / as private");
    return 0; 
  }
  
  /* Make path a mount point for itself as a directory with MS_BIND. This 
   * functions to allow path to function as both a mount point and a 
   * directory, any changes made to the mount point are reflected in it as a
   * directory. Essentially it will act as a chroot directory, after all other  
   * mount points are unmounted.
   */ 
  if( mount(path, path, "ext4", MS_BIND | MS_NOEXEC, "rw,noexec") ){ 
    logErr("sandbox directory appears to be missing");
    return 0; 
  }
  
  /* Make sure to chdir to the path /after/ the mount */ 
  if( chdir(path) ){
    logErr("Failed to cd to sandbox dir, is there a nondir named 'sandbox' at pwd?");
    return 0;
  }
  
 /* Make the directory for the old root for pivot_root, if it already exists 
  * in some form then remove it first so we can assure that it has the correct
  * properties.   
  *
  * It doesn't matter if the remove functions error because we don't even
  * know if oldroot exists (it shouldn't), this  is just an attempt to remove 
  * any existing oldroot file or directory if they exist, ultimately we just 
  * care that mkdir has success in making the new empty directory. 
  */
  rmdir("oldroot");
  unlink("oldroot"); 
  if( mkdir("oldroot",  S_IRUSR |  S_IWUSR | S_IXUSR) ){ 
    logErr("Failed to make oldroot directory, does such a directory " 
           "already exist with files in it? It should be deleted.");
    return 0;
  }
  
  
  /* Simultaneously cause the new root directory to be the sandbox directory, 
   * and the old root directory to be the "oldroot" directory that we just 
   * created, such that the old root directory can be unmounted.  
   */
  if( syscall(SYS_pivot_root, ".", "oldroot") ){
    printf("ERROR: %i", errno);
    fflush(stdout); 
    logErr("Failed to switch root for sandbox");
    rmdir("oldroot");
    return 0; 
  }
  
  /* Switch the processes current directory to be root, which is actually the
   * path which should already be our current directory, however this is 
   * required because it is now the new root. 
   */
  if( chdir("/") ){
    logErr("Failed to chdir to new root for sandbox");
    return 0;
  }
  
  /* Unmount the old root directory and every directory under it, such that the
   * process has no more access to them.  
   */
  if( umount2("oldroot", MNT_DETACH) ){
    logErr("Failed to unmount old root from sandbox");
    return 0; 
  }
  
  /* The old root directory no longer has anything mounted to it, so remove it */
  rmdir("oldroot");
  
  return 1;   
}
