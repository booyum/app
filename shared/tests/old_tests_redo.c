#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <sys/wait.h>

#include "libraries/sec.h"
#include "libraries/logger.h"
#include "misc/enums.h" 

// Must not be compiled with address sanitizer

static int gPassCount;
static int gFailCount;

// Valgrind no memory leaks possible! (additionally tests secFree correctness)  
// though depends on making sure to free everything ^_^

//sec.h tests begin
static void testSecPtr(void);
static void testSecAlloc(void);
static void testSecMemClear(void);
static void testSecFree(void);
static void testSecStrCpy(void);
static void testSec16ConstCmp(void);
static void testSec32ConstCmp(void);
static void test_secto_cast_int2_sizet(void);
static void test_secto_sizet_add_nowrap(void);
static void test_secto_sizet_mul_nowrap(void);
//sec.h tests end

//logger.h tests begin
static void test_initlogger(void);
static void test_logger(void);
static void test_getTimeStamp(void);
//logger.h tests end

int main()
{
  //we must initialize the logger
  initLogger(NULL, UNIT_TEST); 
  
  
  printf("BEGIN TESTING\n"); 
  
  printf("BEGIN sec.h TESTING\n\n");
  testSecPtr();
  testSecAlloc(); 
  testSecMemClear(); 
  testSecFree(); 
  testSecStrCpy(); 
  testSec16ConstCmp(); 
  testSec32ConstCmp(); 
  test_secto_cast_int2_sizet();
  test_secto_sizet_add_nowrap(); 
  test_secto_sizet_mul_nowrap();
  printf("END sec.h TESTING\n\n"); 
  
  printf("BEGIN log.h TESTING\n");
  test_initlogger();
  test_logger();
  test_getTimeStamp(); 
  printf("END log.h TESTING\n");
  
  printf("DONE TESTING\n\n"); 
  
  printf("%i failed, %i passed", gFailCount, gPassCount); 
    
  return 0; 
}

/*
 * sec.h tests
 */


//Tests all ptrSec functions
static void testSecPtr()
{
  printf("BEGIN TESTING secPtr\n"); 
  
  //test pointers
  void *testPointer     = NULL; 
  void *testPointerCopy = testPointer;

  //Make sure initSecPtr initialized correctly
  if( initSecPtr() != 1 ){
    printf("TEST FAIL: initSecPtr failed to initialize\n");
    gFailCount++;
  }
  else{
    printf("TEST PASS: initSecPtr initialized\n");
    gPassCount++; 
  }
   
  //Make sure that initSecPtr doesn't allow for reinitialization
  if( initSecPtr() != 0 ){
    printf("TEST FAIL: initSecPtr failed to block reinitialization\n");
    gFailCount++;
  }
  else{
    printf("TEST PASS: initSecPtr blocked reinitialization\n");
    gPassCount++; 
  }
  
  //encode the testPointer
  testPointer = secPtr(testPointer);
  
  //The pointer should no longer be what it originally was
  if( testPointer == testPointerCopy){
    printf("TEST FAIL: secPtr didn't seem to encode the pointer\n");
    gFailCount++; 
  }
  else{
    printf("TEST PASS: secPtr encoded the pointer\n");
    gPassCount++; 
  }
  
  //Decodes the pointer
  testPointer = secPtr(testPointer); 
  
  //The pointer should be decoded now
  if( testPointer != testPointerCopy ){
    printf("TEST FAIL: secPtr didn't seem to decode the pointer\n");
    gFailCount++;
  }
  else{
    printf("TEST PASS: secPtr decoded the pointer\n");
    gPassCount++; 
  }
  
  printf("END TESTING secPtr\n\n");  
}


static void testSecAlloc(void)
{
  printf("BEGIN TESTING secAlloc\n"); 
  
  int pid;
  int status;
  char warningMuter; 
  
  //secAlloc shouldn't return NULL (unless OOM)
  char *buff = secAlloc(100);
  if( buff == NULL ){
    printf("TEST FAIL: secAlloc didn't allocate memory\n");
    gFailCount++;
  }
  else{
    printf("TEST PASS: secAlloc allocated 100 bytes of memory\n");
    gPassCount++; 
  }
  
  //we should be able to write to the entire allocated memory
  memset(buff, '0', 100); 
  printf("TEST PASS: Wrote to entire memory allocated by secAlloc without"
         "segmentation fault\n"); 
  
  gPassCount++;
  
  
  //and up to the pagesize - 1 after it
  buff[getpagesize() - 1] = '0'; 
  printf("TEST PASS: Wrote to last byte of last non-poisoned page allocated "
         "by secAlloc without segmentation fault\n"); 
  
  gPassCount++;
  
  
  //but anything before it should segfault
   pid = fork();   
   wait(&status);
   
   if(pid == 0){
     buff[-1] = '0'; 
     exit(1); 
   }
   
   if( WTERMSIG(status) != SIGSEGV ){
     printf("TEST FAIL: writing -1 behind secAlloc allocated memory didn't "
            "trigger a segfault\n");
     
     gFailCount++;
   }
   else{
     printf("TEST PASS: writing -1 befind secAlloc allocated memory triggered "
            "a segfault\n");
     
     gPassCount++;
   }
      
  //and so should anything after the last page with allocated bytes
  pid = fork();   
  wait(&status);
  
  if(pid == 0){
    buff[ getpagesize() ] = '0'; 
    exit(1); 
  }
   
  if( WTERMSIG(status) != SIGSEGV ){
    printf("TEST FAIL: writing in the page after last page with allocated "
           "byte didn't trigger a segfault\n");  
    
    gFailCount++;
  }
  else{
    printf("TEST PASS: writing in the page after last page with allocated "
           "byte triggered a segfault\n"); 
    
    gPassCount++; 
  }
  
  
  //and so should reading before it
  pid = fork();   
  wait(&status);
  
  if(pid == 0){
    warningMuter = buff[ -1 ]; 
    exit(1); 
  }
   
  if( WTERMSIG(status) != SIGSEGV ){
    printf("TEST FAIL: reading before allocated byte did not trigger segfault\n"); 
    gFailCount++;
  }
  else{
    printf("TEST PASS: Reading before allocated byte triggered a segfault\n");
    gPassCount++;
  }

  //and so should reading the page after that of the last allocated byte
  pid = fork();   
  wait(&status);
  
  if(pid == 0){
    warningMuter = buff[ getpagesize() ]; 
    exit(1); 
  }
   
  if( WTERMSIG(status) != SIGSEGV ){
    printf("TEST FAIL: reading before allocated byte did not trigger segfault\n"); 
    gFailCount++;
  }
  else{
    printf("TEST PASS: Reading before allocated byte triggered a segfault\n");
    gPassCount++;
  }
  

  //allocating multiple pages should also work
  char *biggerBuff = secAlloc( getpagesize() * 1000 );
  if( biggerBuff == NULL){
    printf("TEST FAIL: secAlloc failed to allocate 1,000 pages\n");
    gFailCount++;
  }
  
  //should be able to write all the way to the end of the last allocated 
  //bytes page
  biggerBuff[ getpagesize() * 1000 - 1] = '0';
  
  printf("TEST PASS: Reading end of last allocated bytes page didn't segfault\n"); 
  gPassCount++; 
  
  //but not beyond the last allocated bytes page
  pid = fork();   
  wait(&status);
  
  if(pid == 0){
    buff[ getpagesize() ] = 'a'; 
    exit(1); 
  }
   
  if( WTERMSIG(status) != SIGSEGV ){
    printf("TEST FAIL: writing beyond last allocated bytes page didn't segfault\n"); 
    gFailCount++;
  }
  else{
    printf("TEST PASS: Writing beyond last allocated bytes page did segfault\n");
    gPassCount++; 
  }
  
  //and not before the first allocated byte
  pid = fork();   
  wait(&status);
  
  if(pid == 0){
    buff[ -1 ] = 'a'; 
    exit(1); 
  }
   
  if( WTERMSIG(status) != SIGSEGV ){
    printf("TEST FAIL: writing before allocated byte did not trigger segfault\n"); 
    gFailCount++;
  }
  else{
    printf("TEST PASS: writing before allocated byte triggered a segfault\n");
    gPassCount++; 
  }
  
  
  //clean up so valgrind accuratley detects memory leaks in called functions
  secFree((void**)&buff, 100); 
  secFree((void**)&biggerBuff, getpagesize() * 1000 );
  
  
  printf("END TESTING secAlloc\n\n");
}


static void testSecMemClear(void)
{
  printf("BEGIN TESTING secMemClear\n");
  
  int buffSize = 10;
  
  //+2 to check for overflow and underflow
  unsigned char testBuff[buffSize + 2];
  
  //make sure that testBuff is initialized to all 'a'
  memset(testBuff, 'a', buffSize + 2);
  if( strncmp((char *)testBuff, "aaaaaaaaaa", buffSize) ){
    printf("TEST FAIL: Failed to initialize memory for secMemClear test\n");
    gFailCount++;
    return; 
  }
  
  //make sure secMemClear errors if it is passed a NULL pointer
  if( secMemClear(NULL, buffSize) ){
    printf("TEST FAIL: secMemClear didn't error when passed a NULL pointer\n");
    gFailCount++;
  }
  else{
    printf("TEST PASS: secMemClear errored when passed a NULL pointer\n");
    gPassCount++;
  }
  
  //make sure secMemClear doesn't error with sane parameters
  if( !secMemClear(testBuff + 1, buffSize) ){
    printf("TEST FAIL: secMemClear returned error\n");
    gFailCount++;
  }
  else{
    printf("TEST PASS: secMemClear didn't return error\n");
    gPassCount++; 
  }
  
  //make sure that buffSize bytes were set to NULL
  if( memcmp(testBuff + 1, "\0\0\0\0\0\0\0\0\0\0", buffSize) ){
    printf("TEST FAIL: secMemClear didn't clear the entire memory buffer\n");
    gFailCount++;
  }
  else{
    printf("TEST PASS: secMemClear cleared the entire memory buffer\n");
    gPassCount++; 
  }
   
  //make sure it didn't underflow
  if( testBuff[0] != 'a' ){
    printf("TEST FAIL: secMemClear underflowed the buffer\n");
    gFailCount++;
  }
  else{
    printf("TEST PASS: secMemClear didn't underflow the buffer\n");
    gPassCount++; 
  }
  
  //make sure it didn't overflow
  if(testBuff[buffSize + 1] != 'a'){
    printf("TEST FAIL: secMemClear overflowed the buffer\n");
    gFailCount++;
  }
  else{
    printf("TEST PASS: secMemClear didn't overflowed the buffer\n"); 
    gPassCount++; 
  }
  
  printf("END TESTING secMemClear\n\n");
}


static void testSecFree()
{
  printf("BEGIN TESTING secFree\n");
  
  unsigned char *testBuff = secAlloc(1000);
  //Make sure the buffer is actually allocated so we can do the tests
  if(testBuff == NULL){
    printf("TEST FAIL: Failed to allocate buffer for testing secFree\n");
    gFailCount++;
    return; 
  }
  
  //make sure secFree errors if given 0 bytes argument
  if( secFree((void**)&testBuff, 0) ){
    printf("TEST FAIL: secFree didn't error with 0 byte argument\n");
    gFailCount++;
  }
  else{
    printf("TEST PASS: secFree errored with 0 byte argument\n");
    gPassCount++; 
  }
  
  //make sure secFree doesn't error when given proper arguments
  if( !secFree((void**)&testBuff, 1000) ){
    printf("TEST FAIL: secFree returned error\n");
    gFailCount++;
  }
  else{
    printf("TEST PASS: secFree didn't return error\n");
    gPassCount++; 
  }
  
  //make sure secFree sets pointer to NULL
  if( testBuff != NULL ){
    printf("TEST FAIL: secFree didn't set the pointer to NULL\n");
    gFailCount++;
  }
  else{
    printf("TEST PASS: secFree set the pointer to NULL\n");
    gPassCount++; 
  }
  
  printf("END TESTING secFree\n\n");
}


static void testSecStrCpy(void)
{
  printf("BEGIN TESTING secStrCpy\n");
  
  //buffBytes is the size we will pretend the buffer is
  size_t buffBytes = 10;
  //Give dst one extra byte to test for overflow 
  char dst[buffBytes + 1];
  memset(dst, '0', buffBytes + 1); 
  
  //pretending the buffer is buffBytes, secStyCpy should copy 
  //up to one less than this many bytes to the buffer regardless of 
  //the bytesize of src
  secStrCpy(dst, "123456789AAAAAAAAAAA", buffBytes); 
  
  //make sure NULL pointers caught
  if( secStrCpy(NULL, "anything", buffBytes) ){
    printf("TEST FAIL: secStrCpy didn't error when passed NULL dst\n"); 
    gFailCount++;
  }
  else{
    printf("TEST PASS: secStrCpy errored when passed NULL dst\n");
    gPassCount++; 
  }
  
  if( secStrCpy(dst, NULL, buffBytes) ){
    printf("TEST FAIL: secStrCpy didn't error when passed NULL src\n"); 
    gFailCount++;
  }
  else{
    printf("TEST PASS: secStrCpy errored when passed NULL src\n");
    gPassCount++; 
  }
  
  //make sure 0 is not a valid bytesize
  if( secStrCpy(dst, "anything", 0) ){
    printf("TEST FAIL: secStrCpy didn't error when told to copy 0 bytes\n");
    gFailCount++;
  }
  else{
    printf("TEST PASS: secStrCpy errored when told to copy 0 bytes\n");
    gPassCount++; 
  }
  
  //Make sure that one less than buffBytes were copied from src to dst
  if( strncmp(dst, "123456789AAAAAAAA", buffBytes - 1) ){
    printf("TEST FAIL: secStrCpy failed to copy --buffBytes from src\n");
    gFailCount++;
  }
  else{
    printf("TEST PASS: secStrCpy copied --buffBytes from src to dst\n"); 
    gPassCount++; 
  }
  
  //Make sure that secStrCpy didn't buffer overflow dst
  if( dst[buffBytes] != '0' ){
    printf("TEST FAIL: secStrCpy wrote beyond buffBytes\n");
    gFailCount++;
  }
  else{
    printf("TEST PASS: secStrCpy didn't write beyond buffBytes\n"); 
    gPassCount++; 
  }
  
  //make sure that secStrCpy NULL terminated dst
  if( dst[buffBytes - 1] != '\0' ){
    printf("TEST FAIL: secStrCpy didn't NULL terminate the string\n");
    gFailCount++;
  }
  else{
    printf("TEST PASS: secStrCpy NULL terminated dst\n");
    gPassCount++; 
  }
  
  //make sure that smaller src string works
  secStrCpy(dst, "abcdef", buffBytes);
  
  //make sure copy worked
  if( strncmp(dst, "abcdef", buffBytes) ){
    printf("TEST FAIL: secStrCpy failed to properly copy small string\n");
    gFailCount++;
  }
  else{
    printf("TEST PASS: secStrCpy successfully copied small string\n");
    gPassCount++;
  }
  
  //make sure NULL terminated after small string copy
  if( dst[ strlen("abcdef") ] != '\0' ){
    printf("TEST FAIL: secStrCpy didn't NULL terminate small string copy\n");
    gFailCount++;
  }
  else{
    printf("TEST PASS: secStrCpy NULL terminated small string copy\n");
    gPassCount++;
  }
  
  printf("END TESTING secStrCpy\n\n");
}


static void testSec16ConstCmp(void)
{
  printf("BEGIN TESTING sec16ConstCmp\n");
  
  int buffSize = 16;
  int x; 
  
  //prepare the buffers
  unsigned char a[buffSize];
  unsigned char b[buffSize];
  
  memset(a, 'z', buffSize);
  memset(b, 'z', buffSize);
  
  //make sure sec16ConstCmp doesn't accept NULL pointers
  if( sec16ConstCmp(NULL, b) != -1 || sec16ConstCmp(a, NULL) != -1 ){
    printf("TEST FAIL: sec16ConstCmp accepts NULL pointer\n");
    gFailCount++;
  }
  else{
    printf("TEST PASS: sec16ConstCmp returns -1 on NULL pointer\n");
    gPassCount++; 
  }
  
  //make sure sec16ConstCmp can identify 16 matching bytes
  if( !sec16ConstCmp(a, b) ){
    printf("TEST FAIL: sec16ConstCmp didn't think matching memory matched\n");
    gFailCount++;
  }
  else{
    printf("TEST PASS: sec16ConstCmp correctly identified matching memory\n"); 
    gPassCount++; 
  }
  
  //make sure sec16ConstCmp can tell when the strings don't match
  for( x = 0 ; x != buffSize ; a[ ++x - 1] = 'z' ){
    a[x] = 'y'; 
    
    if( sec16ConstCmp(a, b) ){
     printf("TEST FAIL: sec16ConstCmp falsely identified matched memory\n");
     gFailCount++;
     break; 
    }
  }
  
  if(x == buffSize){
    printf("TEST PASS: sec16ConstCmp correctly identified mismatched memory\n");  
    gPassCount++;
  }
  
  //test for opposite string mismatch
  for( x = 0 ; x != buffSize ; b[ ++x - 1] = 'z' ){
    b[x] = 'y'; 
    
    if( sec16ConstCmp(a, b) ){
     printf("TEST FAIL: sec16ConstCmp falsely identified matched memory\n");
     gFailCount++;
     break; 
    }
  }
  
  if(x == buffSize){
    printf("TEST PASS: sec16ConstCmp correctly identified mismatched memory\n");  
    gPassCount++;
  }
   
  printf("END TESTING sec16ConstCmp\n\n");
}


static void testSec32ConstCmp(void)
{
  printf("BEGIN TESTING sec32ConstCmp\n");
  
  int buffSize = 32;
  int x; 
  
  //prepare the buffers
  unsigned char a[buffSize];
  unsigned char b[buffSize];
  
  memset(a, 'z', buffSize);
  memset(b, 'z', buffSize);
  
  //make sure sec16ConstCmp doesn't accept NULL pointers
  if( sec32ConstCmp(NULL, b) != -1 || sec16ConstCmp(a, NULL) != -1 ){
    printf("TEST FAIL: sec32ConstCmp accepts NULL pointer\n");
    gFailCount++;
  }
  else{
    printf("TEST PASS: sec32ConstCmp returns -1 on NULL pointer\n");
    gPassCount++;
  }
  
  //make sure sec16ConstCmp can identify 16 matching bytes
  if( !sec32ConstCmp(a, b) ){
    printf("TEST FAIL: sec32ConstCmp didn't think matching memory matched\n");
    gFailCount++;
  }
  else{
    printf("TEST PASS: sec32ConstCmp correctly identified matching memory\n"); 
    gPassCount++;
  }
  
  //make sure sec16ConstCmp can tell when the strings don't match
  for( x = 0 ; x != buffSize ; a[ ++x - 1] = 'z' ){
    a[x] = 'y'; 
    
    if( sec32ConstCmp(a, b) ){
     printf("TEST FAIL: sec32ConstCmp falsely identified matched memory\n");
     gFailCount++;
     break; 
    }
  }
  
  if(x == buffSize){
    printf("TEST PASS: sec32ConstCmp correctly identified mismatched memory\n");  
    gPassCount++;
  }
  
  //test for opposite string mismatch
  for( x = 0 ; x != buffSize ; b[++x - 1] = 'z' ){
    b[x] = 'y'; 
    
    if( sec32ConstCmp(a, b) ){
     printf("TEST FAIL: sec32ConstCmp falsely identified matched memory\n");
     gFailCount++;
     break; 
    }
  }
  
  if(x == buffSize){
    printf("TEST PASS: sec32ConstCmp correctly identified mismatched memory\n"); 
    gPassCount++;
  }
   
  printf("END TESTING sec32ConstCmp\n\n");
}


static void test_secto_cast_int2_sizet(void)
{
  printf("BEGIN TESTING test_secto_cast_int2_sizet\n");
  
  int testInt;
  
  //it is never secure to cast a negative int as an unsigned size_t
  for(testInt = INT_MIN ; testInt < 0 ; testInt++){
    if( secto_cast_int2_sizet(testInt) ){
      printf("TEST FAIL: secto_cast_int2_sizet thought -int could cast\n");
      gFailCount++;
      break;
    }
  }
  
  if( testInt == 0 ){
    printf("TEST PASS: secto_cast_int2_sizet rejected all negative ints\n");
    gPassCount++;
  }
  
  //make sure that if SIZE_MAX is greater than INT_MAX that all positive ints
  //correctly identified as casting to size_t
  if( SIZE_MAX > INT_MAX ){
    for(testInt = 0; testInt < INT_MAX; testInt++){
      if( !secto_cast_int2_sizet(testInt) ){
        printf("TEST FAIL: secto_cast_int2_sizet failed to identify safe cast\n");
        gFailCount++;
        break;
      }
    }
    
    if( testInt == INT_MAX ){
      printf("TEST PASS: secto_cast_int2_sizet identified all safe +int casts\n");
      gPassCount++;
    }
  }
  
  //make sure that if INT_MAX is greater than SIZE_MAX that all ints greater
  //than SIZE_MAX correctly identified as not safe casting
  if( INT_MAX > SIZE_MAX ){  
    for(testInt = 0 ; testInt < INT_MAX; testInt++){
      if(testInt > SIZE_MAX && secto_cast_int2_sizet(testInt)){
        printf("TEST FAIL: unsafe int cast identified as safe\n");
        gFailCount++;
        break;
      }
    }
    
    if(testInt == INT_MAX){
      printf("TEST PASS: all safe int casts identified\n");
      gPassCount++;
    }
  }
  
  printf("END TESTING test_secto_cast_int2_sizet\n\n");
}


static void test_secto_sizet_add_nowrap(void)
{
  printf("BEGIN TESTING secto_sizet_add_nowrap\n");
  
  size_t start;
  size_t end;
  size_t testIterations = 10000;
  
  //test some valid additions and make sure they are detected as not wraparound
  for(start = 0, end = SIZE_MAX ; start != testIterations ; start++, end--)
  {
    if( !secto_sizet_add_nowrap(start, end) ){
      printf("TEST FAIL: Valid addition operation detected as wraparound\n");
      gFailCount++;
      break;
    }
  }
  
  if(start == testIterations){
    printf("TEST PASS: all tested addition operations detected as such\n");
    gPassCount++;
  }
  
  //addition of one to SIZE_NAX should be detected as wraparound
  if( secto_sizet_add_nowrap(SIZE_MAX, 1) ){
    printf("TEST FAIL: adding one to SIZE_MAX not detected as wraparound\n");
    gFailCount++;
  }
  else{
    printf("TEST PASS: adding one to SIZE_MAX detected as wraparound\n");
    gPassCount++;
  }
  
  
  printf("END TESTING secto_sizet_add_nowrap\n\n");
}


static void test_secto_sizet_mul_nowrap(void)
{
  printf("BEGIN TESTING secto_sizet_mul_nowrap\n");
  
  //some basic hardcoded tests
  if( !secto_sizet_mul_nowrap(1, SIZE_MAX) ){
    printf("TEST FAIL: size_max * 1 incorrectly detected as wraparound\n");
    gFailCount++;
  }
  else{
    printf("TEST PASS: size_max * 1 correctly detected as secure\n");
    gPassCount++; 
  }
  
  if( !secto_sizet_mul_nowrap(2, SIZE_MAX / 2) ){
    printf("TEST FAIL: 2 * size_max / 2 incorrectly detected as wraparound\n");
    gFailCount++;
  }
  else{
    printf("TEST PASS: 2 * size_max / 2 correctly detected as secure\n");
    gPassCount++;
  }
  
  if( !secto_sizet_mul_nowrap(0, SIZE_MAX) ){
    printf("TEST FAIL: 0 * SIZE_MAX incorrectly detected as wraparound\n");
    gFailCount++;
  }
  else{
    printf("TEST PASS: 0 * SIZE_MAX correctly detected as secure\n");
    gPassCount++; 
  }
  
  if( secto_sizet_mul_nowrap(2, SIZE_MAX ) ){
    printf("TEST FAIL: 2 * size_max incorrectly detected as secure\n");
    gFailCount++;
  }
  else{
    printf("TEST PASS: 2 * size_max  correctly detected as wraparound\n");
    gPassCount++;
  }
  
  if( secto_sizet_mul_nowrap(3, SIZE_MAX / 2) ){
    printf("TEST FAIL: 3 * size_max / 2 incorrectly detected as secure\n");
    gFailCount++;
  }
  else{
    printf("TEST PASS: 3 * size_max / 2 correctly detected as wraparound\n");
    gPassCount++;
  }
  
  printf("END TESTING secto_sizet_mul_nowrap\n\n");
}





/*
 * logger.h tests
 */
static void test_initlogger(void)
{
  printf("BEGIN TESTING initLogger\n");
  
  if( initLogger(NULL, UNIT_TEST) != 1 ){
    printf("TEST FAIL: initialize logger with UNIT_TEST failed to return 1\n");
    gFailCount++;
  }
  else{
    printf("TEST PASS: initialize logger with UNIT_TEST returned 1\n");
    gPassCount++;
  }
  
  if( initLogger(NULL, PRODUCTION) != 0 ){
    printf("TEST FAIL: initializing logger with NULL in PRODUCTION didn't fail\n");
    gFailCount++;
  }
  else{
    printf("TEST PASS: initializing logger with NULL in PRODUCTION correctly failed\n");
    gPassCount++;
  }
  
  if( initLogger("unit_test_log_delete_me", PRODUCTION) != 1 ){
    printf("TEST FAIL: initialize logger with PRODUCTION failed to return 1\n");
    gFailCount++;
    printf("Cannot continue testing logging functions, aborting unit tests!\n");
    exit(1);
  }
  else{
    printf("TEST PASS: Initialize logger with PRODUCTION returned 1\n");
    printf("TEST PASS: Initialize with PRODUCTION after initialize with UNIT_TEST worked\n"); 
    gPassCount += 2;
  }
  
  if( initLogger("testing", PRODUCTION) != 0 ){
    printf("TEST FAIL: reinitializing logger after init with PRODUCTION didn't fail\n");
    gFailCount++;
  }
  else{
    printf("TEST PASS: reinitializing logger after init with PRODUCTION file correctly rejected\n");
    gPassCount++; 
  }
  
  printf("END TESTING initLogger\n\n");
}


static void test_logger(void)
{
  printf("BEGIN TESTING logger\n");
  
  //TODO ? 
  
  deInitLogger(); 
  
  printf("END TESTING logger\n\n");
}

static void test_getTimeStamp(void)
{
  char timestamp[100]; 
  char compare[100]; 
  memset(timestamp, 'a', 100); 
  memset(compare, 'a', 100);
  
  printf("BEGIN TESTING getTimeStamp\n");
 
  getTimeStamp(timestamp, 100);
    
  if( !memcmp(timestamp, compare, 100) ){
    printf("TEST FAIL: getTimeStamp function didn't set timestamp\n");
    gFailCount++;
  }
  else{
    printf("TEST PASS: getTimeStamp function returned timestamp %s\n", timestamp);
    gPassCount++; 
  }
  
  if( getTimeStamp(NULL, 100) || getTimeStamp(timestamp, 0) ){
    printf("TEST FAIL: getTimeStamp didn't error when given invalid arguments\n");
    gFailCount++;
  }
  else{
    printf("TEST PASS: getTimeStamp did fail when given invalid arguements\n");
    gPassCount++;
  }
  
  
  printf("END TESTING getTimeStamp\n\n");
}