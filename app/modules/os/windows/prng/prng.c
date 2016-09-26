#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "logger.h"
#include "prng.h"


#include <windows.h>
#include <bcrypt.h>



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
 *
 * I've switched out cryptgenrandom for the more modern bcryptgenrandom for 
 * Windows, though this will only run on vista or later. I've also added more 
 * error checking, and have added a return value to signal error. I changed the
 * name from randomBytes to randomize, this is fine since very slight changes 
 * need to be made to tweet NACL anyway, to take the error checking into account.  
 */

/* for systems that aren't windows, use /dev/urandom, 
 * for windows use bcryptgenrandom  */

static BCRYPT_ALG_HANDLE *gWinCngRandom;


/* initializePrng prepares the process for utilizing the kernels PRNG, either 
 * /dev/urandom in the case of everything other than Windows, or BCryptGenRandom
 * in the case of Windows. 
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
  if( gWinCngRandom != NULL ){
    logErr("BCryptGenRandom is already initialized");
    return 0;
  }
    
  if( BCryptOpenAlgorithmProvider( gWinCngRandom, 
                                   BCRYPT_RNG_ALGORITHM, 
                                   NULL, 
                                   NULL)  != STATUS_SUCCESS ){
    logErr("Failed to initialize BCryptGenRandom");
    return 0;
  }
  
  return 1; 
}

/*  randomize uses the kernel PRNG, either /dev/urandom or BCryptGenRandom, to 
 *  fill the buffer pointed to by buff with byteCount bytes. If initializePrng
 *  has not yet been called, randomize will attempt to initialize the PRNG and 
 *  will error on failure to do so.
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
 

  if( gWinCngRandom == NULL && !initializePrng() ){
    logErr("PRNG wasn't initialized, and attempting initialization failed");
    return 0;
  }
     
  if( BCryptGenRandom(*gCryptGenRandom, buff, byteCount, NULL) 
      != 
      STATUS_SUCCESS ){
    logErr("Failed to gather requested bytes from BCryptGenRandom");
    return 0; 
  }
  
  return 1; 
}
