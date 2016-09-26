#define _GNU_SOURCE

/******************************************************************************#
 * Isolate.c implements various forms of isolation, including:
 *
 * 1. Network NS (namespace) isolation, supporting
 *
 *  A. Plain veth networking, whereby a virtual network adapter on the host is 
 *     generated which can be communicated with by the virtual adapter in the 
 *     isolated namespace. In such a case, Tor must have a SocksPort on the 
 *     parent interface, and the primary application logic can then route over
 *     it. This is also known as 'host only routing'.
 *
 *  B. Socat assisted veth networking, which is the same as plain veth 
 *     networking, but with the addition of socat being spawned to listen on the
 *     parent veth, on the same port number as the SocksPort on a device with 
 *     Tor bound to it, and seamlessly forwarding traffic to this port on the 
 *     parent veth to the Tor SocksPort on an arbitrary other device.
 *
 *  C. Existant device pass in, whereby no veths are created and rather a 
 *     networking device that already exists on the system is passed into the 
 *     child namespace, such that it is taken away from the parent namespace.
 *     One example of using this would be if you are in a virtual machine with
 *     host only routing already configured, with Tor already listening on the 
 *     virtual networking adapter of the host, in which case the eth* in the vm
 *     over which traffic can be routed to Tor, can be passed into the child 
 *     namespace where it can continue to be used to route traffic over the Tor
 *     on the host.
 *
 *  Options A and C are the most secure but require the most configuration, 
 *  option B requires no configuration but adds the largest amount of code
 *  in having the addition of socat listening outside of any isolation (TODO
 *  isolate socat, or write own program that is equivalent with isolation?).
 *
 * 2. Filesystem NS isolation, which restricts the process to a directory named 
 *    'sandbox' in the cwd of where execution was initiated (creating this dir if
 *    it does not exist). [Note: currently nothing else is mapped in] 
 *
 * 3. PID, IPC, and UTS NS isolation.
 *
 * 4. SECCOMP Syscall Isolation, of particular note; 
 *    
 *  A. Prevent socket() other than ipv4 TCP 
 * 
 *  B. Prevent sendto() and recvfrom() with direct address specification,
 *     which prevents them from being used for UDP traffic.
 *
 *  C. Prevent connect() other than with a global extern struct sockaddr and 
 *     socklen_t that a preinitialized for the Tor SocksPort, the struct 
 *     sockaddr is additionally set to read only with mprotect such that any 
 *     non-read access to it will immediately segfault.
 *
 *  The combination of (1) and (4) should hopefully go a long way toward 
 *  preventing from memory proxy bypass attacks, (2) should further harden 
 *  this by preventing delayed from the disk proxy bypass attacks, and 
 *  everything together should generally provide a significant degree of 
 *  security via isolation.    
 *
 *                                  AFTER 
 *
 * All of this isolation has been initialized, execution is taken to 
 * isolatedMain, which can be treated like a regular main function but with 
 * the isolation initialized ^_^.   
 *
 *                                  NOTES
 *
 *  1. seccomp requires libseccomp-dev, it is linked with -lseccomp
 *  2. capabilities needs libcap-dev
 *  3. binary needs capabilities: CAP_NET_ADMIN, CAP_SYS_ADMIN, CAP_SETFCAP, +ep 
 *  4. sudo setcap cap_sys_admin,cap_net_admin_cap_setfcap=+ep /path/to/binary
 *
 *  This has been tested with socat method of networking only so far and is a 
 *  work in progress, TODO. 
 *
 ******************************************************************************/

/*****************************ORTHOGONAL HEADER FILES**************************/ 

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <seccomp.h>
#include <sys/capability.h>
#include <unistd.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <features.h>
#include <sys/mount.h>
#include <mntent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <linux/limits.h>
#include <sys/syscall.h>  
#include <sys/stat.h>
#include <sys/utsname.h>
#include <errno.h> 
#include <ifaddrs.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/xattr.h> 
#include <sys/mman.h>
#include <sys/socket.h>
#include <netdb.h>

/*****************************MY HEADER FILES**********************************/

#include "logger.h"
#include "router.h"
#include "sandbox.h"
#include "security.h" 
#include "prng.h"
#include "settings.h"

/*****************************FUNCTION PROTOTYPE INDEX*************************/

//Main after isolation
static int isolatedMain(void);

//Pre isolation initialization
static int preIsolInit(void);
static int initgTors(void);

static int initIsolation(void);


//Isolation initialization
static int finalizeIsolation(void *nullPointer);
static int initSeccomp(void);

static int nameIsolate(void);


//Network namespace functions
static int ipv4WhichDev(char *dev, int devBc, char *ipv4Addr, int ipv4AddrBc);
static int cmpClassCSubnet(char *addrX, int xBc, char *addrY, int yBc);
static int grantIpNetAdmin(void);
static int revokeIpNetAdmin(void);
static int setDevUp(char *dev);
static int setDevIp(char *ip, char *dev);
static int initParVeth(char *childProcNum);
static int initParSocat(char *childProcNum);
static int getRndClassDSub(char *addr, int addrBc, char *matchAddr, int matchAddrBc, char *subnetSlash);
static int initParPassDev(char *childProcNum);
static int initChiVeth(void);
static int initChiPassDev(void);
static int chiGetNonLoDev(char *out, int bc);
static int initChiNet(void);
static int initParNet(char *childProcNum);


//Capability functions
static int setBinCap(char *binPath, char *capString);
static int clearSelfCap(cap_value_t capName);
static int setSelfCap(cap_value_t *capName, cap_flag_t flag, cap_flag_value_t value);

//Misc functions
static int pidToS(char *s, size_t sbc, pid_t pid);
static int forkBin(char *binPath, char *command[], char *envs[], int wait);

/*****************************CONSTANTS****************************************/

enum{ SA_DATA_BC = 14};
enum{ IPV4_S_MAX_BYTES = 16 }; /* 111.222.333.444\0 */ 







/*****************************STATIC GLOBALS***********************************/

static char *gIsolatedStack;   //Pointer for stack for cloned child proc  
static int  rcPipe[2];         //Used to signal initialization complete to child


/****************************MAIN (PRIMARY ENTRY POINT) ***********************/

int main()
{
  if( !preIsolInit() ){
    logErr("Failed to initialize pre-isolation");
    return -1; 
  }

  if( !initIsolation() ){
    logErr("Failed to initialize sandbox");
    return -1; 
  }

  return 0;
}

/*****************************MAIN AFTER ISOLATION*****************************/

/* isolatedMain is the first function called after namespace and SECCOMP 
 * isolation is initialized (ie: it functions as the main of the primary 
 * application). 
 *
 * Returns -1 on error, 0 on success. 
 */
static int isolatedMain(void)
{
  unsigned char *buff = secAlloc(1000); 


  char *isoGui[] = {"Xephyr", "-ac", "-br", "-noreset", "-screen", "1024X900", ":1", NULL };
  char *envs[] = {"DISPLAY=:0", NULL};   

  forkBin("/usr/bin/Xephyr", isoGui, envs, WAIT); 


  sleep(1);
  return 0;

  logMsg("TEST"); 

  routerObj *testRouter = newRouter();
  if( testRouter == NULL ){
    logErr("Failed to make test router new");
    return -1;
  }

  if( !testRouter->methods->torConnect(testRouter) ){
    logErr("Failed to make ipv4 connection");
    return -1;
  }
  
  
  if( !testRouter->methods->socks5Relay(testRouter, "ruger.com", strlen("ruger.com"), 80) ){
    logErr("Failed to handshake");
    return -1; 
  } 
    
   
    
  if( !testRouter->methods->transmit(testRouter, "GET /index.html HTTP/1.1\r\nHost: ruger.com\n\n", 
                                     strlen("GET /index.html HTTP/1.1\r\nHost: ruger.com\n\n") )){
                                       logErr("transmit failed");
                                       return 0; 
                                     }
                                                                     
  if( !testRouter->methods->receive(testRouter, buff, 800) ){
    logErr("Failed to receive bytes");
    return -1;
  } 
  
  printf("%s", buff); 
  
  return 0;
}



/************************PRE ISOLATION INITIALIZATION**************************/


/* preIsolInit bootstraps some things required for the application prior to 
 * initializing the isolation; it prepares the sandbox directory, initializes the
 * log file in the sandbox directory, initializes the PRNG, and initializes the 
 * struct pointed to by gTorSockAddr (as well as the socklen_t gTorAddrLen), 
 * which are used for all connect() syscalls. 
 *
 * Returns 0 on error, 1 on success.
 */
static int preIsolInit(void)
{
  /* Init the PRNG */
  if( !initializePrng() ){
    logErr("Failed to initialize the PRNG");
    return 0;
  }
  
  /* Init the global extern struct sockaddr (and socklen_t) for Tor connect() */ 
  if( !initgTors() ){
    logErr("Failed to initialize the global gTorSockAddr struct for connect");
    return 0; 
  }

  /* Switch to the sandbox directory, create it if it doesn't exist */
  if( !prepsandbox() ){
    logErr("Failed to prepare the sandbox directory");
    return 0; 
  }

  /* Init the log file */ 
  if( !initLogFile("log") ){
    logErr("Failed to initialize log file");
    return 0; 
  }
  
  return 1;
}


/* initgTors initializes the extern globals; struct sockaddr *gTorSockAddr, and 
 * socklen_t gTorAddrLen, which are parameters for use with the connect() 
 * syscall, SECCOMP will whitelist connect() with only these parameters in 
 * furtherance of preventing proxy bypass attacks.  
 *
 * Initialization of gTorSockAddr consists of allocating memory for the 
 * structure and preparing it for the purpose of connect() to the Tor SocksPort.
 * After this struct is initialized in such a fashion, the memory backing it is
 * set to read only such that attempts to overwrite it will immediately segfault.
 * Later in this file, SECCOMP will be used to make it so connect() can only 
 * take the pointer to this structure for its struct sockaddr* parameter.
 *
 * Initialization of gTorAddrLen consists of setting it to the appropriate 
 * value for gTorSockAddr. In a later function, SECCOMP will also whitelist 
 * connect() with only this value. Using read only memory backing is not 
 * required for this value as it is not a pointer to memory but rather is an 
 * integer type.
 *
 * Note: Only supporting IPv4 for Tor:Port
 *
 * Returns 0 on error, 1 on success.
 */
static int initgTors(void)
{
  struct addrinfo *preppedAddr;
  struct addrinfo hints;

  /* Alloc a memory pane for gTorSockAddr, such that we can later freeze it */
  gTorSockAddr = allocMemoryPane(sizeof(struct sockaddr));
  if( gTorSockAddr == NULL ){
    logErr("Failed to allocate the memory for the global Tor sockaddr struct");
    return 0; 
  }
       
  /* Hints allows us to tell getaddrinfo that we are only interested in ipv4 
   * addresses, and also only in TCP (which is implied by SOCK_STREAM). 
   */ 
  hints.ai_family    = AF_INET;
  hints.ai_socktype  = SOCK_STREAM;
  hints.ai_flags     = 0;
  hints.ai_protocol  = 0;
  hints.ai_canonname = NULL;
  hints.ai_addr      = NULL;
  hints.ai_next      = NULL;
  
  //TODO switch between PAR_VETH and TOR_BOUND as needed...
  /* Prepare the address information for addr:port */ 
  if( getaddrinfo( PAR_VETH_STRIPPED, TOR_SOCKS_PORT, &hints, &preppedAddr) ){
    logErr("Failed to encode address"); 
    return 0; 
  }
  
  /* Make sure that the prepared address is IPv4 */ 
  if( preppedAddr->ai_family != AF_INET ){
    logErr("Unexpected family type found, aborting");
    return 0;
  }
  
  /* Multiple structs shouldn't have been obtained because we specified interest
   * in only IPv4 + TCP, however in the case multiple structs are obtained, 
   * attempt using the first returned
   */
  if( preppedAddr->ai_next != NULL ){
    logWrn("Multiple addrinfo structs found when looking up Tor, trying first");
  }
  
   /* gTorAddrLen is the extern global by which we can obtain this value for 
    * the connect() syscall in the router.c code
    */ 
   gTorAddrLen = preppedAddr->ai_addrlen; 
   
   /* copy over the required values to the struct pointed to by gTorSockAddr,
    * such that connect() can use it in the router.c code 
    */ 
   gTorSockAddr->sa_family = preppedAddr->ai_addr->sa_family;
   memcpy(gTorSockAddr->sa_data, preppedAddr->ai_addr->sa_data, SA_DATA_BC); 
   
   /* Freeze the memory pointed to by gTorSockAddr such that any attempts to
    * overwrite it will immediately segfault, this coupled with the SECCOMP
    * rules initialized later on to force connect() to use only this struct,
    * is in furtherance of preventing proxy bypass attacks
    */
   if( !freezeMemoryPane(gTorSockAddr, sizeof(struct sockaddr)) ){
     logErr("Failed to freeze the memory pane of global tor sockaddr");
     return 0; 
   }
   
   /* Free the memory allocated by getaddrinfo */ 
   freeaddrinfo(preppedAddr);
   
  return 1;
}



 

 
/* initIsolation begins the sequence of isolating the primary application logic.
 * First it allocates memory for the stack of the cloned child process, then it
 * initializes a pipe such that it can signal to the child process when it is 
 * finished initializing, after which it creates the child process with clone.
 *
 * The child process is isolated with various namespaces, it will wait for the 
 * pipe to close before doing anything other than basic initialization that 
 * doesn't depend on the state of the parent.  
 *
 * initIsolation will then initialize the networking environment of the parent
 * namespace such that the child will be able to initialize its own networking
 * environment. After this, the parent will signal to the child that it is done
 * with initialization, and then it will wait for the child to terminate.
 *
 * Returns 0 on error, 1 on success.
 */  
static int initIsolation(void)
{ 
  pid_t isolatedProcess;
  char  childProcNum[sizeof(long) + 1];   //++ for null termination TODO MAKE SURE FITS 
  
  /* Allocate the stack for the cloned process, the returned pointer points to 
   * the highest memory address, assuming stack grows downwards as it should on 
   * any x86 architecture (architectures with stacks that grow upwards are not
   * supported).   
   */
  gIsolatedStack = secAlloc(8388608) + 8388608;
  if( gIsolatedStack == NULL ){
    logErr("Failed to allocate stack for isolated PID clone");
    return 0; 
  }
  
   /* Initialize rcPipe, this is used to signal to the cloned child process that
    * the parent process has finished initializing networking such that it can 
    * itself successfully initialize networking without a race condition. 
    */ 
   if( pipe(rcPipe) ){
     logErr("Failed to initialize pipe for synchronizing child and parent proc");
     return 0; 
   }
    
  /* Initialize namespace isolation of; PID, Filesystem, UTS (hostname), network,
   * and IPC. This does so by cloning the process with the appropriate flags, 
   * resulting in the child process (which begins execution at the 
   * finalizeIsolation function) being isolated via namespaces.    
   */
  isolatedProcess = clone( &finalizeIsolation, 
                           gIsolatedStack, 
                           CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUTS | 
                           CLONE_NEWNET | CLONE_NEWIPC | SIGCHLD, 
                           NULL );
  if( isolatedProcess == -1 ){
    logErr("Failed to apply namespace isolation to process (clone)");
    return 0; 
  }
  
  
  /* Get child PID as string in childProcNum */
  if( !pidToS(childProcNum, sizeof(long) + 1, isolatedProcess) ){
    logErr("Failed to get the child pid as a string");
    return 0; 
  }
  
    
  /* Init parent namespace networking (including passing an dev to child) */
  if( !initParNet(childProcNum) ){
    logErr("Failed to configure the virtual network");
    return 0; 
  }
  
  /* Signal to child: Network init responsibilites of parent are satisfied */ 
  if( close(rcPipe[1]) ){
    logErr("Failed to close rcPipe[1] && rcPipe[0] to signal end of parent init");
    return 0; 
  }
  
  /* We don't need any capabilities anymore so relinquish them (TODO here too?) */
  if( !clearSelfCap(CAP_SYS_ADMIN) ||
      !clearSelfCap(CAP_NET_ADMIN) ||
      !clearSelfCap(CAP_SETFCAP)   ){
    logErr("Failed to revoke capabilities");
    return 0;
  }
    
  /* Suspend execution of parent proc while the NS isolated child executes */
  if( waitpid(isolatedProcess, NULL, 0) == -1 ){
    logErr("Had an error waiting on cloned process for sandbox");
    return 0;
  }
    
  return 1; 
}


/*****************************ISOLATION INITIALIZATION*************************/


/* finalizeIsolation is the first function of the child process. 
 * After waiting for the parent process to finish its end of the 
 * network initialization, which is signaled via EOF on the pipe, 
 * it finishes the isolation sequence by initializing the networking 
 * device  of the child process, activating the host/domain namespace 
 * isolation, initializing the mount isolation (such that it is trapped 
 * in the gSandboxPath directory), relinquishing its capabilities, and 
 * activating the SECCOMP syscall whitelist.
 *
 * After this is done, it transfers execution to the isolatedMain function,
 * which functions essentially as a traditional main function, but which is 
 * isolated by namespaces and SECCOMP.
 *
 * Note: nullPointer is not used at all and should be NULL. TODO test with only void
 *
 * Returns 0 on error, 1 on success.
 */
static int finalizeIsolation(void *nullPointer)
{    
  /*********************TODO make pipe nicer**************/    
  /* For holding the detected EOF the parent writes down the pipe */
  char readHolder[1]; 
   
  /* Wait for the parent process to use pipe to signal it has initialized the   
   * network environment 
   */
  close(rcPipe[1]);  
   
  if( read(rcPipe[0], &readHolder, 1) == -1 ){
    logErr("Failed to use pipe to wait, in child process");
    return 0; 
  }     
  
  if( close(rcPipe[0]) ){
    logErr("Failed to close rcPipe[0] in child process");
    return 0; 
  }
  /*********************TODO make pipe nicer**************/  
  
  /* Configure networking from the child namespaces perspective */ 
  if( !initChiNet() ){
    logErr("Failed to initialize the virtual networking for the child\n");
    return 0;
  }
  
  /* Isolate from the hosts domain name and and node name, such that they are 
   * 'spoofed' to "anon" for this process
   */
  if( !nameIsolate() ){
    logErr("Failed to isolate domain and host"); 
    return 0;
  }
  
  /* Isolate from the filesystem, such that the process is trapped in the 
   * directory with the path name pointed to by gSandboxPath
   */ 
  if( !nsFsIsolate() ){
    logErr("Failed to isolate the filesystem");
    return 0;
  }
  
  /* We don't need any capabilities anymore so relinquish them */
  if( !clearSelfCap(CAP_SYS_ADMIN) ||
      !clearSelfCap(CAP_NET_ADMIN) ||
      !clearSelfCap(CAP_SETFCAP)   ){
    logErr("Failed to revoke capabilities");
    return 0;
  }
    
  /* Isolate from kernel syscalls that are not required, via SECCOMP */
/*  if( !initSeccomp() ){*/
/*    logErr("Restricting syscalls failed");*/
/*    return 0;*/
/*  }*/
    
  /* Start the primary application logic */
  if( isolatedMain() ){
    logErr("Failed to initialize the sandboxed application");
    return 0;
  }
  
  return 1; 
}
 
/* initSeccomp initializes the SECCOMP syscall whitelisting, the process of this
 * is documented in the comments of the function itself and is not worth a recap
 * here seeing as it is fairly involved.
 *
 * Returns 0 on error, 1 on success.
 */ 
static int initSeccomp(void)
{
  scmp_filter_ctx filter;
  int ret = 0; 
  
  /* Initialize SECCOMP filter such that non-whitelisted syscalls segfault */
  filter = seccomp_init(SCMP_ACT_KILL);
  if( filter == NULL ){
    logErr("Failed to initialize a seccomp filter");
    return 0;
  }
  
  /* Prepare the syscall filter */
  
  /* NETWORKING SYSCALLS */
  
  /* Only allow sendto with NULL for dest_addr, 0 for addrlen. This prevents
   * this syscall from being used directly to transmit UDP traffic, hardening
   * from proxy bypass attacks. 
   */  
  ret |= seccomp_rule_add( filter, SCMP_ACT_ALLOW, 
                           SCMP_SYS(sendto), 2,  
                           SCMP_CMP( 4 , SCMP_CMP_EQ , 0), 
                           SCMP_CMP( 5 , SCMP_CMP_EQ , 0)
                         );
  
  /* Only allow recvfrom with NULL for src_addr, 0 for addrlen. We don't plan
   * to support receiving UDP traffic, and this /may/ help in preventing some 
   * attacks on anonymity. 
   */   
  ret |= seccomp_rule_add( filter, SCMP_ACT_ALLOW, 
                           SCMP_SYS(recvfrom), 2,
                           SCMP_CMP( 4 , SCMP_CMP_EQ , 0), 
                           SCMP_CMP( 5 , SCMP_CMP_EQ , 0)
                         );
  

  /* Only allow the socket syscall with AF_INET domain (ipv4 only),
   * SOCK_STREAM for type (typically only TCP, certainly not UDP),
   * and with the default protocol (which should be TCP since SOCK_STREAM).
   * In only allowing IPv4 TCP sockets to be created, we prevent all other 
   * forms of proxy bypass. 
   */ 
  ret |= seccomp_rule_add( filter, SCMP_ACT_ALLOW, 
                           SCMP_SYS(socket), 3, 
                           SCMP_CMP( 0 , SCMP_CMP_EQ , AF_INET),
                           SCMP_CMP( 1 , SCMP_CMP_EQ , SOCK_STREAM),
                           SCMP_CMP( 2 , SCMP_CMP_EQ , 0)
                         );
                         
  /* Allow setsockopt only for setting receive timeouts, as used in router.c */
  ret |= seccomp_rule_add( filter, SCMP_ACT_ALLOW, 
                           SCMP_SYS(setsockopt), 2,
                           SCMP_CMP( 1, SCMP_CMP_EQ, SOL_SOCKET), 
                           SCMP_CMP( 2, SCMP_CMP_EQ, SO_RCVTIMEO) 
                         );
   
                           
  /* Only allow connect with the extern global struct addrinfo *gTorSockAddr,
   * the memory backing for which is set to read only with mprotect. This 
   * prevents using connect for anything other than connecting to the Tor
   * SocksPort, which prevents TCP proxy bypass attacks.
   *
   * Additionally only allow with gTorAddrLen, which compliments gTorSockAddr.
   */ 
   ret |= seccomp_rule_add( filter, SCMP_ACT_ALLOW, 
                            SCMP_SYS(connect), 2,
                            SCMP_CMP( 1 , SCMP_CMP_EQ, (scmp_datum_t)gTorSockAddr),
                            SCMP_CMP( 2 , SCMP_CMP_EQ, gTorAddrLen)
                          ); 


  /* MEMORY SYSCALLS */

  /* Allow mprotect unless it is trying to set memory as executable */ 
  ret |= seccomp_rule_add( filter, SCMP_ACT_ALLOW, 
                           SCMP_SYS(mprotect), 1,
                           SCMP_CMP( 2 , SCMP_CMP_NE , PROT_EXEC)
                         );
  
  
  /* SLEEP REQUIRES THESE SYSCALLS */ 
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(rt_sigprocmask), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(rt_sigaction), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(nanosleep), 0);
  
  /* SYSCALLS I HAVE NO IDEA WHY I NEED BUT THINK I DO (TODO) */
 
  /* Generically whitelist these functions for now */
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(write), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(close), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(exit_group), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(open), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(read), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(mmap), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(munmap), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(fstat), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(flock), 0);
  
  /* Make sure that all of the SECCOMP rules were correctly added to filter */
  if( ret != 0 ){
    logErr("Failed to initialize seccomp filter");
    seccomp_release(filter);
    return 1;
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


/* nameIsolate sets domain and node name to "anon".
 * 
 * Returns 0 on error, 1 on success.
 */
static int nameIsolate(void)
{
  return( !sethostname("anon", 4) && !setdomainname("anon", 4) ); 
}


/*************************NETWORK NAMESPACE FUNCTIONS**************************/ 


static int initParSocat(char *childProcNum)
{
  int   ret;
  int   maxBc = 1000;
  char  socatCmdOne[maxBc];
  char  socatCmdTwo[maxBc]; 
 
  /* An example of the socat command utilized, listening on the parent veth on 
   * the same port as the Tor SocksPort, forking such that multiple connections
   * can be forwarded, restricting socat to only the parent veth, and forwarding
   * connections to the addr:port that Tor utilizes;  
   *
   * socat TCP-LISTEN:9051,fork,range=10.42.42.1/24 TCP:192.168.56.1:9051 
   */ 
  char *socatForward[] = {"socat", socatCmdOne, socatCmdTwo, NULL};
  
  /* Basic error checking */
  if( childProcNum == NULL ){
    logErr("Something was NULL that shouldn't have been");
    return 0; 
  }
    
  /* Construct the socat parameter that tells it to listen only on the parent 
   * veth, on the same port as Tor listens on an arbitrary IP address.
   */  
  ret = snprintf( socatCmdOne, 
                  maxBc, 
                  "TCP-LISTEN:%s,fork,range=%s", 
                  TOR_SOCKS_PORT, 
                  PAR_VETH_ADDR );                           
  if( ret == -1 || ret >= maxBc ){
    logErr("Failed to construct socat command string");
    return 0; 
  }
  

  /* Construct the socat parameter that tells it to forward traffic to the Tor
   * SocksPort of an arbitrary IP address.
   */ 
  ret = snprintf( socatCmdTwo, 
                  maxBc, 
                  "TCP:%s:%s", 
                  TOR_BOUND_ADDR, 
                  TOR_SOCKS_PORT ); 
  if( ret == -1 || ret >= maxBc ){
    logErr("Failed to construct socat command string");
    return 0; 
  }

 
  /* Create the veths, passing one to child, and configure the parent veth. */  
  if( !initParVeth(childProcNum) ){
    logErr("Failed to initialize veth pair for socat to listen on");
    return 0; 
  }
  

  /* Actually start socat, note that wait is false, we do not want to wait
   * for it to terminate because it never does.
   */ 
  if( !forkBin("/usr/bin/socat", socatForward, NULL, CONTINUE) ){
    logErr("Failed to initalize socat");
    return 0; 
  }

 
  
  return 1;
}


/* initChiNet initializes networking for the child network namespace. This 
 * consists of ensuring that the ip binary has the proper CAP_NET_ADMIN 
 * capabilities, and then either engaging in the logic for initializing veth 
 * based networking (which includes veth passing with and without socat), or 
 * for passing an already existant device. Finally, the CAP_NET_ADMIN capability 
 * is cleared from the ip binary.
 *
 * returns 0 on error, 1 on success.
 */ 
static int initChiNet(void)
{
  int ret; 

  /* Grant child process, and ip binary, CAP_NET_ADMIN, to configure virt net */
  if( !grantIpNetAdmin() ){
    logErr("Failed to grant the ip program CAP_NET_ADMIN");
    return 0; 
  }  
  
  /* From the child's perspective, socat or veth net_style initialization is 
   * exactly identical.
   */ 
  if      ( NET_STYLE == SOCAT || NET_STYLE == VETH_PAIR ) ret = initChiVeth();
  else if ( NET_STYLE == DEV_PASS                        ) ret = initChiPassDev(); 
  
  /* Basic error checking */
  if( !ret ){
    logErr("Failed to configure the child networking namespace");
    return 0; 
  }

  /* No longer need the CAP_NET_ADMIN capability on child process or ip binary */  
  if( !revokeIpNetAdmin() ){
    logErr("Failed to revoke the CAP_NET_ADMIN cap from self or ip"); 
    return 0; 
  }
  
  return 1; 
}

/* initParNet initializes the networking from the perspective of the parent 
 * networking namespace. This includes ensuring that the IP binary has 
 * CAP_NET_ADMIN set on it, then switching execution to initialize either
 * plain veth, socat supported veth, or existant dev passing networking, then
 * removing CAP_NET_ADMIN from the ip binary.
 *
 * Returns 0 on error, 1 on success. 
 */ 
static int initParNet(char *childProcNum)
{
  int ret = 0;
  
  if( childProcNum == NULL ){
    logErr("Something was NULL that shouldn't have been");
    return 0; 
  }
  
  /* Ensure that ip can be used without root */
  if( !grantIpNetAdmin() ){
    logErr("Failed to grant the ip program CAP_NET_ADMIN");
    return 0; 
  }  
  
  if      (  NET_STYLE == SOCAT     )  ret = initParSocat(childProcNum);
  else if (  NET_STYLE == DEV_PASS  )  ret = initParPassDev(childProcNum); 
  else if (  NET_STYLE == VETH_PAIR )  ret = initParVeth(childProcNum);
  
  if( !ret ){
    logErr("Failed to initialize networking");
    return 0;
  }   

  /* Remove CAP_NET_ADMIN from self and ip binary */
  if( !revokeIpNetAdmin() ){
    logErr("Failed to revoke the CAP_NET_ADMIN cap from self or ip"); 
    return 0; 
  }
 
  return 1;
}


/**************************CAPABILITY FUNCTIONS********************************/ 

/* setIpBinCap sets the current capabilities of the binary at binPath to be
 * the string pointed to by capString. 
 *
 * returns 0 on error, 1 on success.
 */ 
static int setBinCap(char *binPath, char *capString)
{
  cap_t capVal; 
  
  /* Basic error checking */
  if( binPath == NULL || capString == NULL ){
    logErr("Something was NULL that shouldn't have been");
    return 0; 
  }
  
  /* Initialize the cap_t capVal from the string capString */
  capVal = cap_from_text(capString);
  if( capVal == NULL ){
    logErr("Failed to get cap_t");
    return 0; 
  }

  /* Actually set the capability on the binary */
  if( cap_set_file(binPath, capVal) ){
    logErr("Failed to set capabilities on binary");
    if(cap_free(capVal)) logErr("Failed to free capVal");
    return 0; 
  }
  
  /* Free the memory */
  if( cap_free(capVal) ){
    logErr("Failed to free capVal");
    return 0; 
  }
  
  return 1;
}



/* clearSelfCap removes the capability specified by capName from the calling
 * process.
 *
 * Returns 0 on error, 1 on success.
 */
static int clearSelfCap(cap_value_t capName)
{
  cap_value_t *capabilityPointer = &capName;
  
  if( !setSelfCap(capabilityPointer, CAP_EFFECTIVE, CAP_CLEAR) ){
    return 0;
  }
  
  return 1; 
}

/* setSelfCap modifies the capabilities of the calling process
 *
 * returns 0 on error and 1 on success.  
 */
static int setSelfCap(cap_value_t *capName, cap_flag_t flag, cap_flag_value_t value)
{
  cap_t curCaps;
  
  /* Basic error checking */
  if( capName == NULL ){
    logErr("Something was NULL that shouldn't have been");
    return 0;
  }
  
  /* get the current process capabilities */
  curCaps = cap_get_proc();
  if( curCaps == NULL ){
    logErr("Failed to determine current process capabilities");
    return 0; 
  }
  
  /* add the new process capability to the list of current process capabilities */
  if( cap_set_flag(curCaps, flag, 1, capName, value) == -1 ){
    logErr("Failed to add new process capabilities to the list of process capabilities");
    cap_free(curCaps);
    return 0;
  }
  
  /* set the process to use the new capability */
  if( cap_set_proc(curCaps) == -1 ){
    logErr("Failed to set the process to use required new capabilities");
    cap_free(curCaps);
    return 0; 
  }
  
  /* clean up */  
  if( cap_free(curCaps) == -1 ){
    logErr("Failed to free memory associated with process capabilities");
    return 0; 
  }
  
  return 1;
}


/******************************MISC FUNCTIONS**********************************/

/* pidToS takes a pid and writes it as a string to s, which points to sbc bytes 
 * of memory. 
 *
 * Returns 0 on error, 1 on success.
 */ 
static int pidToS(char *s, size_t sbc, pid_t pid)
{
  int ret;
  
  /* Basic error checking */
  if( s == NULL || sbc == 0 ){
    logErr("Something was NULL that shouldn't have been");
    return 0; 
  }

  /* If the size of pid_t is greater than that of long our snprint won't work */
  if( sizeof(pid_t) > sizeof(long) ){
    logErr("Size of long is greater than size of pid_t, cannot snprintf");
    return 0; 
  } 
  
  /* Write the pid as a string into the s buffer */ 
  ret = snprintf(s, sbc, "%li", (long)pid);
  
  /* Check to ensure that no error happened */ 
  if( ret == -1 ){
    logErr("Failed to write the child process ID to a char array");
    return 0; 
  }
  
  /* Check to ensure that no truncation happened */
  if( ret >= sbc ){
    logErr("Failed to write pid string to childProcNum buffer, was truncated");
    return 0; 
  }

  return 1; 
}
 
 
/* forkBin executes the binary at the path named by the string pointed to by 
 * binPath, with the sequence of input words in the NULL pointer terminated 
 * string array pointer to by command. The first input word is, by convention,
 * the name of the binary. 
 *
 * envs is a NULL pointer terminated string array containing environment 
 * variables, or NULL if there are none. 
 *
 * Prior to execution, a fork takes place. The parent fork will either wait for
 * the executed binary to terminate before returning, in the event that wait 
 * is 1 (or WAIT), or it will return immediately even without the executed 
 * binary ever terminating, in the event that wait is 0 (or CONTINUE). 
 *
 * In the event that wait is 0 (or CONTINUE), the pipe the parent process is 
 * using to signal initialization to the namespace isolated cloned child 
 * process will be closed, such that a never terminating fork child will not
 * keep it open, causing the cloned child to hang.
 *
 * A return value of 0 always indicates failure, however success is not assured
 * on a return value of 1 unless no error is logged.   
 */    
static int forkBin(char *binPath, char *command[], char *envs[], int wait)
{ 
  pid_t forkRet;
  
  /* Basic error checking */ 
  if( binPath == NULL || command == NULL ){
    logErr("Something was NULL that shouldn't have been");
    return 0; 
  } 
  
  /*Fork the process into a parent fork and child fork */
  forkRet = fork();
  
  /* There was an error, return 0 */
  if(forkRet == -1){
    return 0;
  } 
  
  /* This is only executed if the current fork is the child, execute the binary,
   * if the parent isn't going to wait for (hinting it never terminates) then 
   * close the pipe, otherwise the pipe will be left open indefinitely and the
   * cloned isolated child process will hang indefinitely. 
   */ 
  if( forkRet == 0){
    if( !wait && close(rcPipe[1]) ){ 
      logErr("Failed to close rcPipe[1] in non-terminating forked child proc");
      return 0; 
    }
 
    if( execve(binPath, command, envs) == -1 ){
      logErr("Fork child failed");
      exit(-1); 
    }
  }
  
  /* This is the parent fork, either return 1 immediately or wait for the child 
   * fork to terminate, depending on the value of wait 
   */ 
  if( forkRet != 0 ){
    if(wait) return(waitpid(forkRet, NULL, 0) != -1); 
    else     return 1; 
  }
  
  return 0; //should never have made it here  
}
