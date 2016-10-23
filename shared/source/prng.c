#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "logger.h"
#include "prng.h"


/* This aims to be a randomBytes replacement, for use with tweet NACL, and 
 * originally inspired by;
 * 
 * https://github.com/ultramancool/tweetnacl-usable/blob/master/randombytes.c
 *
 * I've implemented it as a singleton object with the /dev/urandom file 
 * descriptor kept open and accessible as a static global, such that it can be 
 * utilized with my isolate.c without needing to map /dev/urandom into the new
 * mount namespace, provided it is initialized prior to the namespace filesystem
 * isolation.  
 */


static FILE *gDevuRandom; 

/* initializePrng prepares the process for utilizing the kernels PRNG.
 *
 * This function must be successfully called before the randomize() function 
 * can successfully return, though randomize() will attempt to call this function
 * if it has not already been called, this may fail in the case that /dev/urandom
 * is no longer accessible due to filesystem isolation or similar.
 *
 * Returns 0 on error, 1 on success. 
 */
int initializePrng(void)
{
  if( gDevuRandom != NULL ){
    logErr("/dev/urandom is already open");
    return 0;
  }

  gDevuRandom = fopen("/dev/urandom", "rb");
  if( gDevuRandom == NULL ){
    logErr("Failed to open /dev/urandom");
    return 0;
  }
  
  return 1;  
}

/*  randomize uses the kernel PRNG to fill the buffer pointed to by buff with 
 *  byteCount bytes. If initializePrng has not yet been called, randomize will 
 *  attempt to initialize the PRNG and will error on failure to do so.
 *
 *  Returns 0 on error, 1 on success.   
 */
int randomize(unsigned char *buff, unsigned long long byteCount)
{
  if( buff == NULL ){
    logErr("Something was NULL that shouldn't have been");
    return 0;
  }
  
  if( byteCount == 0 ){
    logWrn("Requesting zero bytes of randomness makes no sense");
    return 1;
  }

  if( gDevuRandom == NULL && !initializePrng() ){
    logErr("PRNG wasn't initialized, and attempting initialization failed");
    return 0;
  }
  
  if( fread(buff, 1, byteCount, gDevuRandom) != byteCount ){
    logErr("Failed to gather requested bytes from /dev/urandom");
    return 0;
  }
  
  return 1; 
}
