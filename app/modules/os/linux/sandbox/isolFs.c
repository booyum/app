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

/* prototypes */
static int preIsolFs(void);
static int writeFsgIsolPath(char *outBuf, size_t bufBc);

/* static globals */
static char *gIsolPath; 

/* isolFs creates a mount point for gIsolPath such that it maps to itself.
 * This allows for modifications to the mount point to transparently map to the
 * actual directory.
 *
 * After gIsolPath is mounted to itself, creates a new temporary directory 
 * "oldroot" in gIsolPath, then pivots root such that gIsolPath is the new root
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
 
int isolFs(void)
{ 
  /* Prepare to initialize namespace mount isolation */
  if( !preIsolFs() ){
    logErr("Failed to prepare to isolate for filesystem isolation");
    return 0; 
  }
  
  /* Initialize the namespace mount isolation */
  if( unshare(CLONE_NEWNS) ){
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
   
  
  /* Make gIsolPath a mount point for itself as a directory with MS_BIND. This 
   * functions to allow gIsolPath to function as both a mount point and a 
   * directory, any changes made to the mount point are reflected in it as a
   * directory. Essentially it will act as a chroot directory, after all other  
   * mount points are unmounted.
   */ 
  if( mount(gIsolPath, gIsolPath, "ext4", MS_BIND, "rw,noexec") ){ 
    logErr("sandbox directory appears to be missing");
    return 0; 
  }
  
  /* Make sure to chdir to the gIsolPath /after/ the mount, even if we were 
   * already pwd at it 
   */ 
  if( chdir(gIsolPath) ){
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
    logErr("Failed to make oldroot directory, does such a directory" 
           "already exist with files in it? It should be deleted.");
    return 0;
  }
  
  
  /* Simultaneously cause the new root directory to be the sandbox directory, 
   * and the old root directory to be the "oldroot" directory that we just 
   * created, such that the old root directory can be unmounted.  
   */
  if( syscall(SYS_pivot_root, gIsolPath, "oldroot") ){ 
    logErr("Failed to switch root for sandbox");
    rmdir("oldroot");
    return 0; 
  }
  
  /* Switch the processes current directory to be root, which is actually the
   * gIsolPath which should already be our current directory, however this is 
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
  
  /* The old root directory no longer has anything mounted to it, so remove it
   */
  rmdir("oldroot");
           
  return 1;   
}




/* preIsolFs prepares the sandbox directory, first it allocates memory to hold
 * the path to the sandbox directory, then it writes to it the string that is the 
 * full path to this directory. The format of the sandbox directory is the current 
 * directory with /sandbox appended to it. After this, it makes this directory with 
 * the appropriate permissions (if the directory doesn't already exist). 
 *
 * Returns 1 on success, 0 on error. 
 */
static int preIsolFs(void)
{
  int ret; 
  
  /* Allocate memory for storing the path to the sandbox directory */
  gIsolPath = secAlloc(PATH_MAX);
  if( gIsolPath == NULL ){
    logErr("Failed to allocate memory to hold gIsolPath");
    return 0; 
  }
   
  /* Writes the current working directory with /sandbox appended to it, into the 
   * memory pointed to by gIsolPath. The path to the sandbox directory is the cwd
   * with /sandbox appended to it. NOTE that it is expected that our binary will 
   * be executed with cd in the directory in which the binary was distributed,
   * however this is not strictly required.  
   */ 
  if( !writeFsgIsolPath(gIsolPath, PATH_MAX) ){
    logErr("Failed to write sandbox path to buffer");
    return 0;
  }
  
  /* Create the sandbox directory if it does not already exist. */ 
  ret = mkdir(gIsolPath, S_IRUSR | S_IWUSR | S_IXUSR); 
  if( ret == 0 ){
    logMsg("sandbox directory didn't already exist, created sandbox directory");
  }
  else if( errno == EEXIST ){
    logMsg("sandbox directory seems to exist, attempting to use it");
  }
  else{
    logErr("Failed to create sandbox directory, and it doesn't already exist");
    return 0; 
  }
   
  /* Switch the processes current directory to the sandbox */
  if( chdir(gIsolPath) ){
    logErr("Failed to cd to sandbox dir, is there a nondir named 'sandbox' at pwd?");  
    return 0;
  }

  return 1; 
}

/* writegIsolPath writes the full path of the sandbox directory to outBuf, which 
 * points to bufBc of memory. The actual sandbox path itself consists of the 
 * current working directory with /sandbox appended to it. If return indicates 
 * success, the full NULL terminated path to the sandbox directory is stored in 
 * outBuff. If buffBc is not enough to store the full NULL terminated path, the 
 * function will return error.
 *
 * Returns 0 on error, 1 on success.
 */
static int writeFsgIsolPath(char *outBuf, size_t bufBc)
{ 
  size_t bytesWrote;
   
  /* Basic error checking */
  if( outBuf == NULL ){
    logErr("Something was NULL that shouldn't have been");
    return 0;
  }
  
  if( bufBc != PATH_MAX ){
    logWrn("Valid sandbox paths may be truncated if bufBc != PATH_MAX");
  }
  
  /* Write current working directory to outBuf, returns NULL if not enough space
   * to store the full NULL terminated path
   */
  if( !getcwd(outBuf, bufBc) ){
    logErr("Failed to write sandbox path to buffer");
    return 0;
  }
  
  /* Calculate the new write position of outBuf, as well as the remaining bc */
  bytesWrote = strnlen(outBuf, bufBc);
  bufBc -= bytesWrote;  
  
  /* Append the current working directory with /sandbox, secStrCpy ensures NULL
   * termination. 
   */
  if( !secStrCpy(&outBuf[bytesWrote], "/sandbox", bufBc) ){
    logErr("Failed to append /sandbox to cwd");
    return 0; 
  }
  
  return 1;   
}

