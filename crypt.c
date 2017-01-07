#define _GNU_SOURCE 
#define _XOPEN_SOURCE 500

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libcryptsetup.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/mount.h>
#include <libmount/libmount.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <dirent.h>
#include <ftw.h>
#include <sched.h> 
#include <sys/syscall.h>  


#include "prng.h" 
#include "argon2.h"
#include "security.h"
#include "isolFs.h"



/* Enums for argon2 parameters */
//enum{PASSES = 400, MEMORY = 125000, THREADS = 4, KEY_BC = 64, PWC_BC = 32, SALT_BC = 32};

enum{PASSES = 1, MEMORY = 32, THREADS = 4, KEY_BC = 64, PWC_BC = 32, SALT_BC = 32};


/* Needs libcryptset-dev, -l cryptsetup */

int newCryptCon(const char *path, const char *devName, char *devPath, uint64_t mb, char *password, size_t pbc);
int mntCryptCon(const char *path, const char *devName, const char *devPath, const char *mntpt, const char *pw, size_t pbc);
static int newDevName(char *out, int outBc);
static int stageTwoIsolFs(const char *mntpt);
static uint64_t mbTob(uint64_t mb);

static uint8_t *genRndFile(const char *path, uint64_t mb);
static int genKey(void *out, size_t obc, const char *pw, size_t pbc, const char *salt, size_t sbc); 
static int mnt(const char *src, const char *dst, const char *fs, const char *options);

int recurseUnimmuteSubdirs(const char *path);
int recurseImmuteSubdirs(const char *path);
static int unimmuteSubDir(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf);
static int immuteSubDir(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf);
static int setDirFlags(const char *path, int flags);

#define DEV_MAPPER_PATH_BC strlen("/dev/mapper/")

int main()
{
  char devName[11]; 
  char devPath[DEV_MAPPER_PATH_BC + 11]; 
  
  if( !initializePrng() ){
    printf("Failed to init prng");
    return -1; 
  }
  
  if( !mitigateForensicTraces() ){
    printf("Failed to disable swap and core dumps");
    return -1; 
  }
  
  if( !newDevName(devName, 11) ){
    printf("Failed to generate a new device name");
    return 0; 
  }
  
  if( !secStrCpy(devPath, "/dev/mapper/", DEV_MAPPER_PATH_BC + 11) ){
    printf("Failed to load /dev/mapper/ into buffer");
    return 0; 
  }
  
  if( !secStrCpy(&devPath[DEV_MAPPER_PATH_BC], devName, 11) ){
    printf("Failed to concatenate device name to /dev/mapper/ string");
    return 0; 
  }
  
  if( !newCryptCon("sandbox/test", devName, devPath, 5, "test", 4) ){
    printf("Failed to create crypto container");
    return -1; 
  }
  
  
  if( !recurseImmuteSubdirs("/media") ){
    printf("Failed to set /media subdirectories to immutable to prevent auto mounting");
    return -1; 
  }
  
  if( !isolFs("sandbox", INIT_FSNS) ){
    printf("Failed to isolate from file system");
    return -1; 
  }
  
  if( !mntCryptCon("/test", devName, devPath, "/hurr", "test", 4) ){
    printf("Failed to mount encrypted container");
    return -1; 
  }
  
  sleep(30); 
  
  return 0;
}

/* Creates a pseudorandom name of outBc - 1 bytes and puts it into out, then 
 * null terminates out buffer. Not intended to be cryptographically secure, 
 * just a quick function to get an alphabetic NULL terminated string that should
 * be pretty unique. 
 *
 * Returns 1 on success, 0 on error. 
 */  
static int newDevName(char *out, int outBc)
{
  char chars[] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
                  'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
                  'y', 'z', '1', '2', '3', '4', '5', '6'};
  
  uint8_t rnd; 
  
  /* Basic error checking */
  if( out == NULL || outBc == 0 ){
    printf("Something was NULL that shouldn't have been");
    return 0; 
  }
  
  /* Ensure NULL termination */
  out[--outBc] = '\0';
  
  /* Go backwards and fill with characters */
  while(outBc--){
    if( !randomize(&rnd, 1) ){
      printf("Failed to randomize a new device name");
      return 0; 
    }
    out[outBc] = chars[rnd % 32];
  } 
  
  return 1;
}



/* getCryptConMeta will read the salt and password check string stored in the 
 * first sector of the crypto container at path, and write them out to the 
 * buffers pointed to by saltOut and pwcOut respectively. The results will not 
 * be NULL terminated, and will have exactly saltBc and pwcBc byte counts, 
 * respectively.
 *
 * Note: The first saltBc bytes of the container are the salt. The next pwcBc
 *       bytes of the container are the password checking string. 
 *       [salt bytes][password checking bytes][dm-crypt bytes].
 *
 * Returns 1 on success, 0 on error.   
 */ 
int getCryptConMeta(const char *path, char *saltOut, size_t saltBc, char *pwcOut, size_t pwcBc)
{
  int fd;
  uint8_t *mm; 
  
  /* Basic error checking */
  if( path == NULL ){
    printf("Something was NULL that shouldn't have been");
    return 0; 
  }
  
  /* Open the crypto container file, we will be reading in the password checker
   * and the salt, which are stored in its first sectory.
   */ 
  fd = open(path, O_RDONLY);
  if( fd == -1 ){
    printf("Failed to open crypto container at path, does it not exist?");
    return 0; 
  }
  
  /* Memory map the open crypto container file such that we can read from a 
   * pointer to it.
   */ 
  mm = mmap(NULL, 512, PROT_READ, MAP_PRIVATE, fd, 0);
  if( mm == MAP_FAILED ){
    printf("Failed to create memory mapping to the crypto container file");
    return 0; 
  }
  
  /* Copy out the salt bytes if the saltOut buffer isn't NULL */
  if(saltOut) memcpy(saltOut, mm, saltBc);
  
  /* Copy out the password check bytes if the pwcOut isn't NULL */
  if(pwcOut) memcpy(pwcOut, &mm[saltBc], pwcBc);
  
  
  /* No longer need the file descriptor */
  if( close(fd) ){
    printf("Failed to close the crypto container file descriptor");
    return 0; 
  }
  
  /*no longer need the memory mapping */
  if( munmap(mm, 512) ){
    printf("Failed to unmap the crypto container from memory");
    return 0;
  }  
  
  return 1; 
}


int mntCryptCon(const char *path, const char *devName, const char *devPath, const char *mntpt, const char *pw, size_t pbc)
{
  struct libmnt_context *mntCtx; 
  struct crypt_params_plain options;
  struct crypt_device *cryptCon;
  char key[KEY_BC + PWC_BC];
  char salt[SALT_BC];
  char pwChecker[PWC_BC];
  
  /* Basic error checking */
  if( path == NULL || mntpt == NULL || pw == NULL || pbc == 0 ){
    printf("Something was NULL that shouldn't have been");
    secMemClear(key, KEY_BC + PWC_BC);
    return 0;
  }
  
  /* Obtain the salt and password checker container in the first sector of 
   * crypto container 
   */ 
  if( !getCryptConMeta(path, salt, SALT_BC, pwChecker, PWC_BC) ){
    printf("Failed to get metadata from the crypto container");
    secMemClear(key, KEY_BC + PWC_BC);
    return 0;
  }
  
  /* Use the password and salt to generate the key and password checker. 
   * The first KEY_BC of the key buffer will contain the key, and the 
   * next PWC_BC bytes will container the password checker, which is to be
   * compared with the password checker obtained from the first sector of the
   * crypto container in order to verify a correct password was provided
   */
  if( !genKey(key, KEY_BC + PWC_BC, pw, pbc, salt, SALT_BC) ){
    printf("Failed to generate key");
    secMemClear(key, KEY_BC + PWC_BC);
    return 0;
  }
  
  /* Make sure that the password checker generated with the provided password 
   * and salt matches the stored password checker from the first sector of the
   * crypto container, in order to verify that the password was correct. Failure 
   * to do this could result in mounting with an incorrect key and data corruption.
   */ 
  if( memcmp(pwChecker, &key[KEY_BC], PWC_BC) ){
    printf("Provided password doesn't work with this crypto container");
    secMemClear(key, KEY_BC + PWC_BC);
    return 0; 
  }

  
  /* Initialize the crypto container at path and reference it with cryptCon */
  if( crypt_init(&cryptCon, path) ){
    printf("Failed to initialize the crypto container");
    secMemClear(key, KEY_BC + PWC_BC);
    return 0;
  }
  
  /* Set the dm-crypt options, hash SHA-512, offset one sector because we use 
   * the first sector to store metadata (salt, password checker). Use the first 
   * sector after the offset for storing the initialization vector. Autodetect 
   * the size by setting to 0.   
   */ 
  options.hash   = "sha512";
  options.offset = 1;
  options.skip   = 0;
  options.size   = 0; 
  
  /* Because this is CRYPT_PLAIN rather than luks it will not actually format 
   * the container, but is apparently the correct function for loading the 
   * encryption options to the cryptCon struct. 
   */  
  if( crypt_format(cryptCon, CRYPT_PLAIN, "aes", "xts-plain64", NULL, key, KEY_BC, &options) ){
    printf("Failed to set the properties of the encryption container");
    secMemClear(key, KEY_BC + PWC_BC);
    return 0; 
  }
  
  /* Activate the device with the key */ 
  if( crypt_activate_by_volume_key(cryptCon, devName, key, KEY_BC,  0  ) ){ 
    printf("Failed to activate the crypto container");
    secMemClear(key, KEY_BC + PWC_BC);
    return 0; 
  }
  
  /* Mount the device to mntpt */
  if( !mnt(devPath, mntpt, "ext4", "offset=512") ){
    printf("Failed to mount the encrypted container in the child namespace");
    secMemClear(key, KEY_BC + PWC_BC);
    return 0; 
  }
  
  /* Pivot root into the newly mounted encrypted container and disconnect from 
   * all of the rest of the file system 
   */
  if( !stageTwoIsolFs(mntpt) ){
    printf("Failed to isolate into the encrypted mount point");
    secMemClear(key, KEY_BC + PWC_BC);
    return 0; 
  }
  
  /* Free the cryptCon context seeing as we no longer need it */ 
  crypt_free(cryptCon);
  
  /* Securely clear the key from the buffer */
  secMemClear(key, KEY_BC + PWC_BC);
  
  return 1; 
}

/* stageTwoIsolFs is for creating another new mount namespace after the 
 * encrypted container has been mounted in the child namespace. After the 
 * new namespace is created, pivot root into the mount point of the encrypted 
 * container and disconnect from the entire parent filesystem.
 *
 * Returns 1 on success, 0 on error.
 */ 
static int stageTwoIsolFs(const char *mntpt)
{
  /* Basic error checking */
  if( mntpt == NULL ){
    printf("Something was NULL that shouldn't have been");
    return 0; 
  }
  
  /* Create the second new mount namespace */ 
  if(unshare(CLONE_NEWNS) ){
    printf("Failed to unshare the filesystem");
    return 0; 
  } 
  
  /* Change current directory to be the mount point of encrypted container */ 
  if( chdir(mntpt) ){
    printf("Failed to cd to the mount point of the encrypted container");
    return 0;
  }
  
  /* Remove any existing oldroot directory (it may not exist) and then make a 
   * new one with the appropriate permissions
   */ 
  rmdir("oldroot");
  unlink("oldroot"); 
  if( mkdir("oldroot",  S_IRUSR |  S_IWUSR | S_IXUSR) ){ 
    printf("Failed to make oldroot directory, does such a directory" 
           " already exist with files in it? It should be deleted.");
    return 0;
  }
  
  /* Pivot root into the mount point of the encrypted container */
  if( syscall(SYS_pivot_root, ".", "oldroot") ){
    printf("Failed to switch root for sandbox");
    rmdir("oldroot");
    return 0; 
  }
  
  /* Switch the process's cwd to be root, which is where we should already be 
   * however this is required because it is now the new root
   */ 
  if( chdir("/") ){
    printf("Failed to chdir to new root for sandbox");
    return 0;
  }
  
  /* Unmount the old root directory and every directory under it, such that the 
   * process has no more access to them.
   */ 
  if( umount2("oldroot", MNT_DETACH) ){
    printf("Failed to unmount old root from sandbox");
    return 0; 
  }
  
  /* The old root directory no longer has anything mounted to it, so remove it */ 
  rmdir("oldroot");
  
  return 1;
}

/* mnt will mount the device at path src to the directory at path dst, using 
 * the filesystem type fs, and the options string options. 
 *
 * Returns 1 on success, 0 on error.
 */
static int mnt(const char *src, const char *dst, const char *fs, const char *options)
{
  struct libmnt_context *ctx; 
  
  /* Basic error checking */
  if( src == NULL || dst == NULL || fs == NULL || options == NULL ){
    printf("Something was NULL that shouldn't have been");
    return 0; 
  }
  
  /* Get a new context for libmount */ 
  ctx = mnt_new_context();
  if( ctx == NULL ){
    printf("Failed to get new mount context");
    return 0; 
  }
  
  /* Add the options to the context (for example, offset=512) */
  if( mnt_context_append_options(ctx, options) ){
    printf("failed adding options to context");
    return 0; 
  }
  
  /* Add the source to the context (for example, /dev/mapper/name) */
  if( mnt_context_set_source(ctx, src) ){
    printf("failed adding source to context");
    return 0; 
  }
  
  /* Add the destination to the context (for example, /sandbox/something) */
  if( mnt_context_set_target(ctx, dst) ){
    printf("failed adding target to context");
    return 0;
  }
  
  // TODO play with settings here and also look into specifically MS_PRIVATE
  
  /* Add the filesystem type to the context (for example, ext4) */
  if( mnt_context_set_fstype(ctx, fs) ){
    printf("failed adding fs type to context");
    return 0; 
  }
  
  /* Actually perform the mount operation */ 
  if( mnt_context_mount(ctx) ){
    printf("failed to mount");
    return 0;
  }
  
  /* Free the memory associated with the mount context */ 
  mnt_free_context(ctx);
  
  return 1;
}

/* genKey runs the argon2 pbkdf with the appropriate inputs (and the constant 
 * enums defined at the top of this file) and outputs the generated key of 
 * obc byte count to the buffer out.
 *
 * Returns 1 on success, 0 on error.
 */ 
static int genKey(void *out, size_t obc, const char *pw, size_t pbc, const char *salt, size_t sbc)
{
  /* Basic error checking */
  if( out == NULL || obc == 0 || pw == NULL || pbc == 0 || salt == NULL || sbc == 0 ){
    printf("Something was NULL that shouldn't have been");
    return 0; 
  }
  
  /* Generate the key */ 
  if( argon2i_hash_raw(PASSES, MEMORY, THREADS, pw, pbc, salt, sbc, out, obc) != ARGON2_OK ){
    printf("Failed to derive a key from the password");
    return 0;  
  }
  
  return 1;
}

/* mbTob returns the number of bytes required to represent mb megabytes, or 0 
 * on error. Note that it is an error to convert 0 megabytes to bytes, though 
 * this will correctly return 0 on error. If the mb value cannot be converted 
 * to bytes without integer wrap around, will error and return 0. This function 
 * uses 1 mb = 1,000 kb = 10,000 bytes. 
 *
 * On success returns the number of bytes in mb megabytes. On error returns 0.
 */ 
static uint64_t mbTob(uint64_t mb)
{
  uint64_t bc; 
  
  /* Basic Error Checking */
  if( mb == 0 ) return 0;
  
  
  /* Convert requested megabytes into requested kilobytes, using 1,000 */ 
  if( secto_mul_uint64t(mb, 1000) ){
    bc = mb * 1000;
  }
  else{
    printf("Converting from megabytes to kilobytes will wrap around");
    return 0; 
  }
  
  /* Convert requested kilobytes into requested bytes, using 1,000 */ 
  if( secto_mul_uint64t(bc, 1000) ){
    bc *= 1000; 
  }
  else{
    printf("Converting from kilobytes to bytes will wrap around");
    return 0; 
  }
  
  return bc;
}

/* genRndFile generates a random file at the location given in path. The file 
 * will consist of mb megabytes of cryptographically secure pseudorandomness.
 *
 * Returns pointer to mmaped container on success, NULL on error.
 */  
static uint8_t *genRndFile(const char *path, uint64_t mb)
{
  int      fd; 
  void     *mm;
  uint64_t bc;
  
  /* Basic error checking */
  if( path == NULL || mb == 0 ){
    printf("Something was NULL that shouldn't have been");
    return NULL; 
  }
  
  bc = mbTob(mb);
  if( bc == 0 ){
    printf("Failed to convert megabytes to bytes");
    return NULL; 
  }
  
  /* Create the file, open with these flags prevents TOCTOU */ 
  fd = open(path, O_EXCL | O_CREAT | O_RDWR | O_LARGEFILE, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);  
  if( fd == -1 ){
    printf("Failed to open file, does it already exist?");
    return NULL; 
  } 
  
  /* Fill the entire file with zeros such that it is exactly bc bytes long. This
   * is required so that mmap will allow us to map the entire byte count of the 
   * file into memory such that it can be entirely randomized.
   */ 
  if( ftruncate(fd, bc) ){
    printf("Failed to zero fill new container file");
    unlink(path); 
    return NULL;
  }
  
  /* Make a memory mapping to the file so we can write randomness to it */
  mm = mmap(NULL, bc, PROT_WRITE | PROT_READ, MAP_SHARED, fd, 0);
  if( mm == MAP_FAILED ){
    printf("Failed to create memory mapping to file");
    unlink(path); 
    return NULL; 
  }
  
  /* Randomize the file */ 
  if( randomize(mm, bc) == -1 ){
    printf("Failed to randomize the encryption container");
    unlink(path); 
    return NULL; 
  }
  
  /* Close the file descriptor */
  if( close(fd) ){
    printf("Failed to close the file descriptor");
    unlink(path); 
    return NULL; 
  }
  
  return mm; 
}

/* newCryptCon creates a new encrypted container file, using ext4 filesystem, 
 * at path. The container file will be mb megabytes, and will be encrypted with 
 * a key derived from the supplied password. The first SALT_BC bytes of the 
 * container will consist of a salt used with the password for the argon2 
 * PBKDF, the next PWC_BC bytes of the file will consist of a password 
 * checking string that is used for confirming the correct password is used 
 * for generating the key for decryption. devName and devPath must be 
 * appropriately formed strings (a device name, and /dev/mapper/device_name,
 * respectively) that are used for initial mounting of the container such that 
 * the filesystem can be generated on it.
 *
 * Returns 1 on success, 0 on error.
 */  
int newCryptCon(const char *path, const char *devName, char *devPath, uint64_t mb, char *password, size_t pbc)
{
  char *mkfs[] = {"mke2fs", devPath, "-t", "ext4", "-E", "offset=512", NULL};
  struct crypt_device *cryptCon;
  struct crypt_params_plain options;
  uint8_t      *mm;
  uint64_t bc; 
  
  char key[KEY_BC + PWC_BC]; 
  
  /* Basic error checking */
  if( path == NULL || mb == 0 ){
    printf("Something was NULL that shouldn't have been");
    return 0; 
  }
  
  /* Generate an initial random file to use as container */ 
  mm = genRndFile(path, mb); 
  if( !mm ){
    printf("Failed to generate random file for crypto container");
    return 0; 
  }
  
  /* Generate the key from the password and salt. Using the pointer to the 
   * first byte of the random file and reading SALT_BC from it, the first 
   * SALT_BC of the randomly generated file are used as the salt. An additional 
   * PWC_BC bytes are generated with the argon2 PBKDF, which will be written 
   * to the encrypted container after the salt such that it can be used to 
   * verify correct password in the future. Note that we offset by one sector 
   * when using the crypto container, this should give us at least 512 bytes 
   * to play with.  
   */ 
  if( !genKey(key, KEY_BC + PWC_BC, password, pbc, mm, SALT_BC) ){
    printf("Failed to generate a key for crypto container");
    unlink(path); 
    return 0; 
  }
  
  /* Write the last PWC_BC bytes of the generated key to the crypto container, 
   * offset by SALT_BC. These bytes will be used to verify the correct password 
   * has been utilized in the future.
   */ 
  memcpy(&mm[SALT_BC], &key[KEY_BC], PWC_BC);
  
  /* Determine the number of bytes */
  bc = mbTob(mb);
  if( bc == 0 ){
    printf("Failed to convert megabytes to bytes");
    unlink(path); 
    return 0; 
  }
  
  /* We no longer need the mapping into the crypto container, so unmap it! */ 
  if( munmap(mm, bc) ){
    printf("Failed to unmap memory");
    unlink(path); 
    return 0;
  } 
  
  /* Initialize the crypto container such that the cryptCon struct is associated 
   * with it.
   */
  if( crypt_init(&cryptCon, path) ){
    printf("Failed to initialize the crypto container");
    unlink(path); 
    return 0;
  }
  
  /* Set the dm-crypt options, hash SHA-512, offset one sector because we use 
   * the first sector to store metadata (salt, password checker). Use the first 
   * sector after the offset for storing the initialization vector. Autodetect 
   * the size by setting to 0.   
   */ 
  options.hash   = "sha512";
  options.offset = 1;
  options.skip   = 0;
  options.size   = 0; 
  
  /* Set the cipher, mode of operation, key, and options to use for the encryption */
  if( crypt_format(cryptCon, CRYPT_PLAIN, "aes", "xts-plain64", NULL, key, KEY_BC, &options) ){
    printf("Failed to format the crypto container");
    unlink(path); 
    return 0; 
  }
  
  /* Activate the crypto container */ 
  if( crypt_activate_by_volume_key(cryptCon, devName, key, KEY_BC, 0 ) ){ 
    printf("Failed to activate the crypto container");
    unlink(path); 
    return 0; 
  }
  
  /* Fork execve to create a file system on it (omg no C api for this anywhere) */ 
  switch( fork() ){
    /* on error */
    case -1:
      printf("Failed to fork to create file system on crypto container");
      return 0; 
    /* Child execve mke2fs and make filesystem on mounted encrypted container */ 
    case 0:
      if( execve("/sbin/mke2fs", mkfs, NULL) ){
        printf("Failed to execve to mke2fs to make file system on crypto container");
        unlink(path); 
        exit(-1); 
      } 
    /* Parent sleep for two seconds to give ample time for child to complete 
     * the operation. TODO find a way to make this event driven. 
     */ 
    default:
      sleep(2);
  }
  
  /* Deactive the encryption container such that it is no longer mounted nor 
   * associated with a virtual device 
   */ 
  if( crypt_deactivate(cryptCon, devName) ){
    printf("Failed to deactivate the crypto container");
    unlink(path); 
    return 0;
  }
  
  /* Free the cryptCon context seeing as we no longer need it */ 
  crypt_free(cryptCon); 	
  
  /* Securely erase the key from the buffer. If any step fails the crypto 
   * container will not be utilizable and therefore there is no need to 
   * clear the key from the buffer because a new salt will be used next 
   * attempt and will result in a different key. 
   */
  secMemClear(key, KEY_BC + PWC_BC); 
  
  return 1;
}

/* recurseImmuteSubdirs will set the immutable flag on all first layer 
 * sub-directores of path, removing any currently set flags in the process.
 *
 * Returns 1 on success, 0 on error. In the event of error some sub-dirs may 
 * be immutable still.
 */ 
int recurseImmuteSubdirs(const char *path)
{
  /* Basic error checking */
  if( path == NULL ){
    printf("Something was NULL that shouldn't have been");
    return 0; 
  }
  
  /* Set all sub directories that are exactly one layer removed from path to be
   * immutable, (removing all other flags in the process). 
   */ 
  if( nftw(path, immuteSubDir, 5, FTW_CONTINUE) ){
    return 0; 
  }
  
  return 1;
}

/* recurseUnimmuteSubdirs will clear all flags on all first layer 
 * sub-directores of path, removing the immutable flag in the process. 
 *
 * Returns 1 on success, 0 on error. In the event of error some sub-dirs may 
 * still have flags set on them. 
 */ 
int recurseUnimmuteSubdirs(const char *path)
{
  /* Basic error checking */
  if( path == NULL ){
    printf("Something was NULL that shouldn't have been");
    return 0; 
  }
  
  /* Set all sub directories that are exactly one layer removed from path to be
   * immutable, (removing all other flags in the process). 
   */ 
  if( nftw(path, unimmuteSubDir, 5, FTW_CONTINUE) ){
    return 0; 
  }
  
  return 1;
}



/* immuteSubDir is intended to be used only as a callback function for nftw, it 
 * will ignore the original directory, set first layer sub directories to immutable,
 * and ignore everything else. Not using FTW_SKIP_SUBTREE because it doesn't appear
 * to work as expected.
 */ 
static int immuteSubDir(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
  /* Skip this if it is not exactly one layer removed from the original path, 
   * also skip it if it is not a directory.
   */ 
  if(ftwbuf->level != 1 || typeflag != FTW_D){
    return FTW_CONTINUE; 
  }
  
  /* Otherwise set this sub-directory, which is exactly one layer removed from
   * the original path, to be immutable.
   */ 
  if( !setDirFlags(fpath, FS_IMMUTABLE_FL) ){
    printf("Failed to set one of the sub-directories to immutable");
    return FTW_STOP;
  }
  
  /* Continue on */ 
  return FTW_CONTINUE;
}


/* unimmuteSubDir is intended to be used only as a callback function for nftw, it 
 * will ignore the original directory, set first layer sub directories to immutable,
 * and ignore everything else. Not using FTW_SKIP_SUBTREE because it doesn't appear
 * to work as expected.
 */ 
static int unimmuteSubDir(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
  /* Skip this if it is not exactly one layer removed from the original path, 
   * also skip it if it is not a directory.
   */ 
  if(ftwbuf->level != 1 || typeflag != FTW_D){
    return FTW_CONTINUE; 
  }
  
  /* Otherwise set this sub-directory, which is exactly one layer removed from
   * the original path, to have no flags (clearing immutable flag). 
   */ 
  if( !setDirFlags(fpath, 0) ){
    printf("Failed to set one of the sub-directories to immutable");
    return FTW_STOP;
  }
  
  /* Continue on */ 
  return FTW_CONTINUE;
}


/* setDirFlags sets the chflags of the directory at path to the flags defined 
 * by 'flags', which can be a single flag or a bitwise OR of flags. If flags 
 * is 0 then all flags will be removed. This function doesn't preserve previous 
 * flags.
 *
 * Returns 1 on success, 0 on error.
 */ 
static int setDirFlags(const char *path, int flags)
{
  DIR *dir;
  
  /* Basic error checking */
  if( path == NULL ){
    printf("Something was NULL that shouldn't have been");
    return 0; 
  }
  
  /* Initialize the directory pointer */
  dir = opendir(path);
  if( !dir ){
    printf("Failed to open directory");
    return 0; 
  }
  
  /* Modify flag */
  if( ioctl(dirfd(dir), FS_IOC_SETFLAGS, &flags) == -1 ){
    printf("Failed to modify the directory flag");
    return 0; 
  } 
  
  /* Deinitialize directory pointer */
  if( closedir(dir) ){
    printf("Failed to close directory");
    return 0; 
  }
  
  return 1; 
}
