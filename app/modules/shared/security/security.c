#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sched.h>

#include <errno.h>

#include "security.h"
#include "logger.h"


static int dataIndependentCmp(unsigned char *x, unsigned char *y, int n);
static int memClear(volatile uint8_t *memoryPointer, size_t bytesize);

/*******************ALLOCATION SECURITY FUNCTIONS******************************/

/* allocMemoryPane returns bytesRequested of read/write memory rounded up to be 
 * a multiple of the memory page bytesize. After allocation, this memory can be
 * frozen with a call to freezeMemoryPane, this will cause a defensive segfault
 * if the memory is written to again. 
 *
 * Returns a pointer to the first allocated byte on success, NULL on error.
 */
void *allocMemoryPane(size_t bytesRequested)
{
  void *memoryPane;
  size_t pageBytesize; 
  size_t requiredPages;
  
  /* It makes no sense to allocate a memoryPane of 0 bytes */ 
  if( bytesRequested < 1 ){
    logErr("Cannot memoryPane fewer than one byte");
    return NULL;
  }
  
  /* We want to work with the page bytesize as a size_t rather than long.
   * 
   * This proves the cast is safe and then makes it.  
   */ 
  if( !secto_cast_long2_sizet(sysconf(_SC_PAGESIZE)) ){
    logErr("Invalid integer operation detected");
    return NULL;  
  }
  else{
    pageBytesize = (size_t)sysconf(_SC_PAGESIZE);
  }
  
  /* To calculate the pages required to meet our allocation obligation we will
   * first divide bytesRequested by the pageBytesize, however we may need to 
   * add one to this, in the event that requested bytes is not a multiple of 
   * pageBytesize.
   *
   * This proves that the integer operation is valid and then does it. 
   */
  if( !secto_sizet_add_nowrap(bytesRequested / pageBytesize , 1) ){
    logErr("invalid integer operation detected");
    return NULL;  
  }
  else{
    requiredPages = bytesRequested / pageBytesize;
    if(bytesRequested % pageBytesize) requiredPages++;
  }
 
  /* When we tell mmap how many bytes to allocate we will compute it by 
   * multiplying the page bytesize by the number of required pages we 
   * determined were needed, this is a proof that the integer operation 
   * is valid
   */ 
  if( !secto_sizet_mul_nowrap(requiredPages, pageBytesize) ){
    logErr("invalid integer operation detected");
    return NULL;  
  }
  

  /* Allocate the requiredPages * pageBytesize bytes of memory. mmap guarantee
   * page alignment allowing for mprotect, allocating the memory originally 
   * to write and read capable 
   */   
  memoryPane = mmap( NULL, 
                   requiredPages * pageBytesize, 
                   PROT_WRITE | PROT_READ,
                   MAP_PRIVATE | MAP_ANONYMOUS,
                   -1, 0 );
  if( memoryPane == MAP_FAILED ){
    logErr("Failed to mmap memory for the memoryPane");
    return NULL;  
  }   

  return memoryPane;                                    
}

/* freezeMemoryPane sets the page(s) pointed to by memoryPane to be read only,
 * such that writing to it will cause a defensive segfault. bytesize is the 
 * full bytesize of the memory pane, OR the number of bytes that the user 
 * requested for allocation in a call to allocMemoryPane or secAlloc, either
 * number will work just as well as the other 
 *
 * Returns 0 on error, 1 on success.
 */ 
int freezeMemoryPane(void *memoryPane, size_t bytesize)
{
  /* Basic error checking */
  if( memoryPane == NULL || bytesize == 0 ){
    logErr("Something was NULL that shouldn't have been");
    return 0;
  }
  
  /* Make sure the memory is read only */  
  if( mprotect( memoryPane, bytesize, PROT_READ ) ){
    logErr( "Failed to unlock memoryPane");
    return 0; 
  }
  
  return 1;
}


/* secAlloc allocates at least bytesRequested bytes of memory, though it will 
 * go over to the nearest full page. Page guards are allocated as delimiters to
 * the allocated pages, such that any access (read,write,execute) to the page 
 * guards will segfault the process, in furtherance of preventing linear heap 
 * buffer overflow attacks.
 *
 * [guard][page][guard]
 *
 * Every allocation is at least 3 memory pages, one for the requested allocated
 * bytes, and two for page guard delimiters, typically 12,288 bytes. Page guards
 * will typically utilize virtual memory only.
 *
 * All non-page-guard-pages are NULL filled.
 *
 * On error returns NULL pointer, on success returns pointer to the first 
 * non-poisoned byte.
 *
 * Note that the non-poisoned allocated memory can be frozen with a call to
 * freezeMemoryPane, in other words the returned pointer is to a memory pane
 * of bytesRequested bytes rounded up to be a multiple of a memory page, which 
 * is itself enclosed by two page guards.   
 */
void *secAlloc(size_t bytesRequested)
{
  void   *memBuff;
  size_t requiredPages; 
  size_t pageBytesize;
  
  /* Basic error checking */
  if( bytesRequested == 0 ){
    logErr("Cannot allocate zero bytes of memory");
    return NULL;  
  }
  
  /* We want to work with the page bytesize as a size_t, but 
   * sysconf(_SC_PAGESIZE) returns it as a long. Make sure that it is secure to
   * cast it to a size_t, and if it is assign it cast as size_t to pageBytesize. 
   */
  if( !secto_cast_long2_sizet(sysconf(_SC_PAGESIZE)) ){
    logErr("Invalid integer operation detected");
    return NULL;  
  }
  else{
    pageBytesize = (size_t)sysconf(_SC_PAGESIZE);
  }
    
  /* We need to compute the total number of pages we need to allocate, which
   * will be the minimum number required to meet the bytesRequested requirement
   * in addition to two more for the page guards. 
   *
   * Initially we can divide the number of bytes requested by the bytesize of 
   * a page to determine how many pages will be required, then after confirming
   * it is secure to do so, we can add two to this number and assign it to 
   * requiredPages. Note that unsigned division is inherently a secure operation.  
   *
   * Because the division operation will floor the result, we will need to add
   * one to the value of requiredPages, because (5/10) will evaluate to 0, but
   * if 5 bytes are requested and the page size is 10, we still need one page.
   * To take this possible additional ++ into account, we initially ensure that
   * 3 can be added to bytesRequested / pageBytesize, though in some cases only
   * 2 would be required. 
   */
  if( !secto_sizet_add_nowrap(bytesRequested / pageBytesize , 3) ){
    logErr("invalid integer operation detected");
    return NULL;  
  }
  else{
    requiredPages = (bytesRequested / pageBytesize) + 2;
    if(bytesRequested % pageBytesize) requiredPages++;
  }
  

  /* We can compute the total allocation bytesize by multiplying the previously
   * computed requiredPages by pageBytesize, however first ensure that this
   * multiplication operation will not wrap around. 
   */
  if( !secto_sizet_mul_nowrap(requiredPages, pageBytesize) ){
    logErr("invalid integer operation detected");
    return NULL;  
  }
  
  /* Allocate the required memory pages, aligned to page boundaries such that 
   * we can use mprotect on them, with mmap for poxic compliance, 
   */ 
  memBuff = mmap( NULL, 
                  requiredPages * pageBytesize, 
                  PROT_WRITE | PROT_READ, 
                  MAP_PRIVATE | MAP_ANONYMOUS, 
                  -1, 0 ); 
  if( memBuff == NULL ){
    logErr("Failed to allocate memory");
    return NULL; 
  }  

  
  /* mprotect the page guards such that any access to them will segfault the 
   * process (free still works). 
   */
  if( mprotect(memBuff, 1, PROT_NONE) 
      ||
      mprotect(memBuff + ((requiredPages - 1) * pageBytesize), 1, PROT_NONE)
    ){
    logErr("Failed to initialize page guards");
    free(memBuff); 
    return NULL;
  }
  
  /* NULL fill the pages that are not guards */   
  memset(memBuff + pageBytesize, '\0', (requiredPages - 2) * pageBytesize );
    
  /* Return a pointer to first non-poisoned byte */
  return memBuff + pageBytesize; 
}


/****************************CLEAR SECURITY FUNCTIONS**************************/ 


/* memClear is an internal memory clearing function not meant to be called 
 * outside of the file due to lacking a memory barrier, use the secMemClear 
 * entry point. 
 */
static int memClear(volatile uint8_t *memoryPointer, size_t bytesize)
{
  if( memoryPointer == NULL ) return 0; 
  while(bytesize--) *memoryPointer++ = 0; 
  return 1; 
}


/* secMemClear clears the byte array of bytesize bytes pointed to by 
 * memoryPointer, in compliance with MEM03-C. 
 *
 * Additionally, it then uses an assembly memory barrier to further 
 * ensure that the clear is not optimized out by the compiler, as 
 * demonstrated here; https://sourceware.org/ml/libc-alpha/2014-12/msg00506.html  
 *
 * Returns 0 on error, 1 on success. 
 */
int secMemClear(volatile uint8_t *memoryPointer, size_t bytesize)
{
  /* memoryPointer is checked for NULL by memClear */

  /* First clear buffer with a volatile pointer, in accordance with MEM03-c */
  if( !memClear(memoryPointer, bytesize) ){ 
    logErr("Failed to clear buffer");
    return 0;
  }  

  /* Then attempt to access it with assembly, to further ensure clear is not 
   * optimized out */
  __asm__ __volatile__ ( "" : : "r"(*memoryPointer) : "memory" );
     
  return 1; 
}


/***************************FREE SECURITY FUNCTIONS****************************/

/* secFree is the free function for memory allocated with secAlloc. When passed
 * a pointer to a pointer pointing to the first non-poisoned byte of memory 
 * allocated with secAlloc, secFree will clear bytesize bytes (which should be
 * the bytesRequested from secAlloc), then it will free the entire memory 
 * from the first byte of the first page guard to the last byte of the last 
 * page guard. After this, the pointer pointed to by dataBuffer will be set 
 * to NULL.
 *
 * Valgrind tested to ensure free of all memory is with success.
 *
 * Clearing in compliance with MEM03-C, additionally with assembly memory 
 * barrier to further prevent optimizing the clear out.
 *
 * Pointer set to NULL in compliance with MEM01-C.
 *
 * Returns 0 on error, 1 on success.
 */ 
int secFree(void **dataBuffer, size_t bytesize)
{
  /* Basic error checking */ 
  if(dataBuffer == NULL || *dataBuffer == NULL){
    logErr("Something was NULL that shouldn't have been"); 
    return 0;
  }
  
  /* More basic error checking */
  if(bytesize == 0){
    logErr("Zero bytes of memory is invalid"); 
    return 0; 
  }
  
  /* Clear the buffer */   
  if( !secMemClear(*dataBuffer, bytesize) ){
    logErr("Failed to clear memory buffer"); 
    return 0; 
  }  
                
  /* Free the memory starting from the first byte of the first page guard. 
   * Keep in mind that this is the free coupled with secAlloc, which uses page
   * guards. 
   */
  free( *dataBuffer - sysconf(_SC_PAGESIZE) );  
      
  /*Set the pointer pointed to by dataBuffer to NULL, in compliance with 
   * MEM01-C */
  *dataBuffer = NULL; 
  
  return 1; 
}


/***********************STRING SECURITY FUNCTIONS******************************/

/* secStrCpy copies src into dst, up to and including the NULL terminator
 * of src, unless doing so would overflow dst, in which case one less than 
 * dstBytesize bytes will be copied from src into dst (truncating src), and 
 * dst will be NULL terminated.
 *
 * Returns NULL on error, on success a pointer to the first byte of dst.  
 */
char *secStrCpy(char *dst, char *src, size_t dstBytesize)
{
  /* Basic error checking */
  if(dst == NULL || src == NULL){
    logErr("Something was NULL that shouldn't have been");
    return NULL; 
  }
  
  /* More basic error checking */
  if(dstBytesize == 0){
    logErr("Destination buffer must be at least one byte");
    return NULL;
  }
  
  /* Example illustration when src would overflow
   *
   * Source: [a][b][c][d][e][f][g][\0] 
   * Destin: [0][1][2]
   * dstByt: 3
   * result: [a][b][2]
   * termin: strnlen(src, 3 - 1) = 2
   * result[2] = '\0'
   * result: [a][b][\0] 
   *
   * Example illustration when perfect fit
   *
   * Source: [a][b][c][d][\0]
   * Destin: [0][1][2][3][4]
   * dstByt: 5
   * result: [a][b][c][d][\0]
   * termin: strnlen(src, 5 - 1) = 4
   * result[4] = '\0'
   * result: [a][b][c][d][\0] 
   *
   * Example illustration when src would underflow
   *
   * Source: [a][\0]
   * Destin: [0][1][2][3][4]
   * dstByt: 5
   * result: [a][\0][2][3][4]
   * termin: stnlen(src, 5 - 1) = 1
   * result[1] = '\0'
   * result: [a][\0][2][3][4] 
   */ 
  
  /* Copy src up to and including terminating NULL, and put into dst. 
   * if src is longer than dstBytesize - 1 bytes, verbatim copy the first 
   * dstBytesize - 1 bytes from src and put into dst (in which case NULL 
   * termination is not certain) */
  strncpy(dst, src, dstBytesize - 1); 
  
  /* Ensure that dest is NULL terminated */  
  dst[ strnlen(src, dstBytesize - 1) ] = '\0'; 
  
  return dst; 
}

/* sec16ConstCmp compares the 16 bytes pointed to by x against the 16 bytes
 * pointed to by y in constant time.
 *
 * Returns 1 on match, 0 on mismatch, -1 on error
 */ 
int sec16ConstCmp(unsigned char *x, unsigned char *y)
{
  return dataIndependentCmp(x, y, 16);   
}

/* sec32ConstCmp compares the 32 bytes pointed to by x against the 16 bytes
 * pointed to by y in constant time.
 *
 * Returns 1 on match, 0 on mismatch, -1 on error
 */ 
int sec32ConstCmp(unsigned char *x, unsigned char *y)
{
  return dataIndependentCmp(x, y, 32);
}

/* dataIndependentCmp compares the n bytes pointed to by x against the n bytes
 * pointed to by y, in data independent time.
 *
 * Returns 1 on match, 0 on mismatch, -1 on error.
 */
static int dataIndependentCmp(unsigned char *x, unsigned char *y, int n)
{  
  int checker = 0;
  
  if( x == NULL || y == NULL ){
    logErr("Something was null that shouldn't have been");
    return -1; 
  }
  
  while(n--) checker |= x[n] ^ y[n]; 
  
  return !checker; 
}


/***********************INTEGER SECURITY FUNCTIONS*****************************/

/* secto_cast_long2_sizet determines if it is safe to cast the long x to a 
 * size_t.
 *
 * Returns 0 if it is not safe to cast, 1 if it is safe to cast.
 */
inline int secto_cast_long2_sizet(long x)
{
  return ( x >= 0 && x <= SIZE_MAX );  
}

/* secto_cast_int2_sizet determines if it is safe to cast the int x to a size_t.
 *
 * Returns 0 if it is not safe to cast, 1 if it is safe to cast.
 */
inline int secto_cast_int2_sizet(int x)
{
  return ( x >= 0 && x <= SIZE_MAX );  
}

/* secto_sizet_add_nowrap determines if it safe to add the size_t x to the 
 * size_t y, without wrapping.
 *
 * Returns 0 if the addition operation will wrap, 1 if it will not.
 */ 
inline int secto_sizet_add_nowrap(size_t x, size_t y)
{
  return (SIZE_MAX - x) >= y;   
}

/* secto_sizet_mul_nowrap determines if it is safe to multiply the size_t x by
 * the size_t y, without wrapping.
 *
 * Returns 0 if the multiplication operation will wrap, 1 if it will not.
 */
inline int secto_sizet_mul_nowrap(size_t x, size_t y)
{
  if( x == 0 || y == 0 ) return 1; 
  return (SIZE_MAX / x) >= y;  
}

/* secto_add_int determines if it is safe to add the int x to the int y, without
 * overflowing. 
 *
 * Returns 0 if the addition operation will overflow, 1 if it will not.
 */ 
inline int secto_add_int(int x, int y)
{
  if(x > 0 && x > INT_MAX - y) return 0;
  if(x < 0 && y < INT_MIN - x) return 0;
  return 1;
}
 
/* secto_add_uint determines if it is safe to add the unsigned int x to the 
 * unsigned int y, without wrap around.
 *
 * Returns 0 if the addition operation will wrap, 1 if it will not.
 *
 * Compliant with INT32-c
 */
inline int secto_add_uint(unsigned int x, unsigned int y)
{
  return !(UINT_MAX - x < y);
}



/**************************SYSTEM SECURITY FUNCTIONS***************************/

/* disableCoreDumps completely disables core dumps for the process by setting
 * their maximum size to 0 bytes.
 *
 * Returns 0 on error, 1 on success. 
 */
int disableCoreDumps(void)
{
  struct rlimit limit; 
  limit.rlim_cur = 0;
  limit.rlim_max = 0;
  if(setrlimit(RLIMIT_CORE, &limit)){
    logErr("Failed to disable core dumps");
    return 0; 
  } 
  
  return 1; 
}





/* secClone is clone wrapped with its own stack allocation using the secAlloc
 * function, not currently supporting ability for arguments, returns -1 on 
 * error, and the pid_t of the cloned process on success. */ 
pid_t secClone(int (*execFunct)(void *), int flags)
{
  void *stack;
  pid_t ret;
  
  if( execFunct == NULL ){
    logErr("Something was NULL that shouldn't have been");
    return -1; 
  }

 /* Allocate the stack for the cloned process, the returned pointer points to 
  * the highest memory address, assuming stack grows downwards as it should on 
  * any x86 architecture (architectures with stacks that grow upwards are not
  * supported).   
  */
  stack = secAlloc(8388608) + 8388608;
  if( stack == NULL ){
    logErr("Failed to allocate stack for isolated PID clone");
    return -1; 
  }

 /* Do a clone with flags but no arguments to the function pointed to by 
  * execFunct, using the previously allocated stack. 
  */
  ret = clone(execFunct, stack, flags, NULL);
  if(ret == -1){
    logErr("Failed to clone to a new process");
    return -1; 
  }
  
  return ret;
}
