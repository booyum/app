#define _GNU_SOURCE

#include <seccomp.h>
#include <sys/mman.h>
#include <sched.h>
#include <sys/types.h>         
#include <sys/socket.h>
#include <string.h>
#include <netdb.h>
#include <sys/un.h>
#include <poll.h>
#include <errno.h> 

#include "isolNet.h"
#include "security.h"
#include "logger.h"
#include "settings.h"
#include "net.h"

enum{ SA_DATA_BC = 14, NS = 0, TOR = 1};


static int initRedirector();


/* Used to signal that the network redirector is initialized */ 
static int stoplight[2];  


/******************************PARENT PROCESS**********************************/

/* The parent process has the task of cloning off to the redirector process, 
 * which uses a listening Unix Domain Socket to get connections from the child
 * network namespace, which it then redirects to the Tor SocksPort. 
 *
 * The parent process blocks waiting for the redirector to be initialized, after
 * which it initializes the network namespace for its own process (not the 
 * redirector process, which cannot be contained to a network namespace due to
 * needing to communicate with Tor which is not in the child namespace). 
 */

/* isolNet initializes the network isolation. It returns 1 on success, 
 * and 0 on error.
 */ 
int isolNet(int initRedirector)
{
  char throwAway[1]; 
  
  /* Make sure the initRedirector value is valid */
  if( initRedirector != REDIRECT && initRedirector != SIMPLE ){
    logErr("The value passed to isolNet was invalid");
    return 0; 
  }
  
  /* If we are simply to initialize the network namespace without a redirector 
   * then do so, otherwise we continue on for the redirection logic
   */ 
  if( initRedirector == SIMPLE ){
    if( unshare(CLONE_NEWNET) ){
      logErr("unshare clone_newnet failed");
      return 0;
    }
    return 1;
  }
  
  /* Initialize the pipe the redirector process uses to signal initialization */ 
  if( pipe(stoplight) ){
    logErr("Failed to initialize the pipe for signaling redirector inited");
    return 0; 
  }
  
  /* Clone off to the network redirector process */
  if( secClone(&initRedirector, 0) == -1 ){
    logErr("Failed to clone into redirector for network activity");
    return 0; 
  } 
  
  /* Close the write pipe of this process */
  if( close(stoplight[1]) ){
    logErr("Failed to close the parents write pipe");
    return 0; 
  }
  
  /* Block waiting for the cloned redirector process to signal it initialized */ 
  if( read(stoplight[0], &throwAway, 1) == -1 ){
    logErr("Failed to determine if network redirector initialized");
    return 0; 
  }
  
  /* Put this process (not redirector) into a new network namespace. Note that 
   * this requires the CAP_SYS_ADMIN capability. 
   */ 
  if( unshare(CLONE_NEWNET) ){
    logErr("Failed to isolate with network namespaces");
    return 0; 
  }
  
  return 1; 
}


/******************************REDIRECTOR PROCESS******************************/

/* The redirector process listens on a Unix Domain Socket for connections from 
 * the client namespace, after which it forwards them to the Tor SocksPort. 
 * Every new incoming connection from the client namespace results in a forked
 * process for managing the redirection of that connection, this is in essence 
 * the same behavior as would be expected from using forking socat redirection.
 */ 


/*************************REDIRECTOR SPECIFIC PROTOTYPES***********************/

/* These functions are only used by the redirector logic */ 

static void redirect(int unixListen);
static int  getTorSock(void);
static int  initgTors(void);
static int  seccompWl(void);



/*************************REDIRECTOR SPECIFIC GLOBALS**************************/

/* These globals are only used by the redirector logic. 
 * 
 * gTorAddr and gTorLen will be used for all connect() syscalls for connecting 
 * to the Tor SocksPort. Only these will be able to be used with connect(), this
 * is enforced by SECCOMP. The memory pointed to by *gTorAddr will itself be 
 * mprotected to read only, such that attempts to overwrite it segfault.
 */  

static struct sockaddr  *gTorAddr;   
static socklen_t        gTorLen;  


/*************************REDIRECTOR SPECIFIC FUNCTIONS************************/

/* initRedirector initializes the redirector process that listens on a Unix 
 * Domain Socket for connections from the child network namespace, and then 
 * transparently forwards them to the Tor SocksPort. Because it is started 
 * with a call to clone, the return value is never reachable, however it 
 * returns 0 on error, and should never return on success. 
 *
 * Note: This function doesn't return void only because clone wants a function 
 * pointer with this prototype. 
 */ 
static int initRedirector() 
{
  /* The Unix Domain Socket for listening */ 
  int unixListen;
  
  /* Initialize the static globals utilized for connect() to the SocksPort */ 
  if( !initgTors() ){
    logErr("Failed to initialize the static globals for getting connection to Tor");
    return 0;
  }
  
  /* Initialize the SECCOMP syscall whitelist for the redirector process */ 
  if( !seccompWl() ){
    logErr("Failed to SECCOMP the network redirector");
    return 0; 
  }
  
  
  /* Begin listening on the Unix Domain Socket for connections from child NS */ 
  unixListen = udsListen("/tor_unix_socket", strlen("/tor_unix_socket"));
  if( unixListen == -1 ){
    logErr("Failed to bind unix domain socket for redirector");
    return 0;
  }
  
  /* Begin the actual redirector logic, this should never return */  
  redirect(unixListen); 
  
  /* If we made it here something went wrong, redirect should never return */ 
  return 0; 
}

/* redirect waits for new incoming connections from the client namespace, after
 * a new connection is accepted it will fork off to a new process that manages 
 * the actual redirection logic whereby connections from the child network NS 
 * are transparently redirected to the Tor SocksPort, then will continue waiting
 * for more new connections from the child namespace ad infinitum.
 *
 * redirect has as its parameter an int which must be an already listening 
 * Unix Domain Socket. This function never returns.
 */ 
static void redirect(int unixListen)
{
  static int         initialized;
  struct sockaddr_un remote;
  int                clientIncoming;
  int                ret; 
  int                len;
  socklen_t          structLen;
  int                torSock; 
  void               *buff;
  
  
  /* A pointer to this is used with the accept syscall */ 
  structLen = sizeof(struct sockaddr_un);
  
  /* Begin the infinite loop in which we wait for incoming connections from the
   * child namespace, accept them, and then fork off into a new process that 
   * redirects them to the Tor SocksPort, ad infinitum.
   */ 
  while(1){
    /* Establish a new connection to the Tor SocksPort. */ 
    torSock = getTorSock();
    if(torSock == -1){
      continue; 
    }
    
    /* If we have not already done so, signal to the parent process that we are
     * initialized to the point that we can accept connections from the child 
     * network namespace. 
     */ 
    if(!initialized){
      close(stoplight[0]); 
      close(stoplight[1]);  //TODO make this a do while loop and put outside at top so not checking like this
      initialized = 1; 
    }
    
    /* Block waiting for connections from the child network namespace, then 
     * accept them when they come in. 
     */  
    clientIncoming = accept(unixListen, &remote, &structLen);
    if( clientIncoming == -1 ){
      close(torSock); 
      continue; 
    }
    
    /* Now that we've an established connection from the child network namespace,
     * fork off into a new process for handling it
     */ 
    ret = fork();
    
    /* If we failed to fork off a new process, close the sockets and continue */
    if( ret == -1 ){
      close(torSock);
      close(clientIncoming);
      continue;
    }
    
    /* If this is the parent fork, continue blocking waiting for new connections */
    if( ret != 0 ) continue;
    
    /* Otherwise, this is the child fork for managing the redirection. */
    
    /* Prepare to use poll */
    int pollRet; 
    struct pollfd fds[2];
    

    
    /* Allocate a buffer for holding traffic to/from Tor */ 
    buff = secAlloc(4096);
    if( buff == NULL ){
      logErr("Failed to allocate buffer for the redirector");
      return;
    }
    
    /* Continuously receive bytes from the child namespace, send to the Tor 
     * SocksPort, receive the response from the Tor SocksPort, send to the 
     * child namespace. When the socket is no longer in use, this will currently
     * block indefinitely at the first recv
     */ 
    while(1){
      /* Prepare poll structs */
      
      /* Detect incoming and outgoing traffic, + disconnect, on clientIncoming */
      fds[NS].fd      = clientIncoming;
      fds[NS].events  = POLLIN | POLLRDHUP;
      fds[NS].revents = 0;
    
      /* Detect incoming and outgoing traffic, + disconnect, on torSock */
      fds[TOR].fd      = torSock;
      fds[TOR].events  = POLLIN | POLLRDHUP;
      fds[TOR].revents = 0;
      
      /* Block forever waiting for an event */ 
      pollRet = poll((struct pollfd *)&fds, 2, -1);
      if( pollRet == -1 ){
        logErr("Poll had an error in the redirector");
        exit(-1); 
      }
      
      /* End this process if either of the remote sockets disconnected */
      if( (fds[NS].revents & POLLRDHUP) || (fds[TOR].revents & POLLRDHUP) ){
        exit(0); 
      }
      
      /* If there are bytes from the child network namespace, receive and forward */
      if( fds[NS].revents & POLLIN ){ 
        len = recv(clientIncoming, buff, 4096, MSG_DONTWAIT);
        if( len == -1 && errno != EAGAIN && errno != EWOULDBLOCK ){
          logErr("Redirector failed to receive bytes from child namespace");
          exit(-1); 
        }
      
        len = send(torSock, buff, len, 0);
        if( len == -1 ){
          logErr("Redirector failed to send bytes to the Tor SocksPort");
          exit(-1); 
        }
      }
      
      /* If there are bytes from Tor, receive and forward */ 
      if( fds[TOR].revents & POLLIN ){ 
        len = recv(torSock, buff, 4096, MSG_DONTWAIT);
        if( len == -1  && errno != EAGAIN && errno != EWOULDBLOCK ){
          logErr("Redirector failed to receive bytes from Tor");
          exit(-1);  
        }
       
        len = send(clientIncoming, buff, len, 0);
        if( len == -1 ){
          logErr("Redirector failed to send bytes to the child namespace");
          exit(-1); 
        }
      }
      
    }
  }
}

/* getTorSock returns a socket to the Tor SocksPort on success or -1 on error */ 
static int getTorSock(void)
{
  int torSock;
  
  /* Get the socket for connecting to the Tor SocksPort */
  torSock = socket(AF_INET, SOCK_STREAM, 0);
  if( torSock == -1 ){
    logErr("Failed to get socket");
    return -1;
  }
  
  /* Connect to the Tor SocksPort */ 
  if( connect(torSock, gTorAddr, gTorLen) ){
    close(torSock); 
    logErr("Failed to get a connection to Tor SocksPort");
    return -1; 
  }
  
  return torSock;
}


/* initgTors initializes the static global struct sockadd and socklen_t used for
 * the connect() syscalls the redirector process makes to the Tor SocksPort. 
 *
 * The memory pointed to by gTorAddr is mprotected to read only after 
 * initialization, such that if it is overwritten the process will immediately
 * segfault. 
 *
 * Note that the connect() syscall itself will be SECCOMP whitelisted such that
 * the redirector process can only use gTorAddr and gTorLen as arguments for it,
 * and that if separate arguments are used the process will immediately segfault.
 * Taken together, this should prevent proxy bypass attacks in the event that 
 * the redirector process is compromised.
 *
 * Note that we only support SocksPort being on IPv4 addresses. 
 *
 * Returns 1 on success, 0 on error.
 */ 
static int initgTors(void)
{
  struct addrinfo *preppedAddr;
  struct addrinfo hints;
  
  /* Alloc a memory pane for gTorAddr, such that we can later freeze it */
  gTorAddr = allocMemoryPane(sizeof(struct sockaddr));
  if( gTorAddr == NULL ){
    logErr("Failed to allocate the memory for the global Tor sockaddr struct");
    return 0; 
  }
  
  /* Hints allow us to tell getaddrinfo that we are only interested in 
   * SocksPorts on IPv4 addresses, and with TCP (which is implied by SOCK_STREAM).  
   */ 
  hints.ai_family    = AF_INET;
  hints.ai_socktype  = SOCK_STREAM;
  hints.ai_flags     = 0;
  hints.ai_protocol  = 0;
  hints.ai_canonname = NULL;
  hints.ai_addr      = NULL;
  hints.ai_next      = NULL;
  
  /* Prepare the address information for addr:port */ 
  if( getaddrinfo(TOR_ADDR, TOR_PORT, &hints, &preppedAddr) ){
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
  
  /* gTorLen is the static global that the redirector will use for accessing 
   * the value of preppedAddr->ai_addrlen for all of its connect() syscalls. 
   */ 
  gTorLen = preppedAddr->ai_addrlen; 
  
  /* copy over the required values to the struct pointed to by gTorSockAddr,
   * such that it is initialized for connect() syscalls. 
   */ 
  gTorAddr->sa_family = preppedAddr->ai_addr->sa_family;
  memcpy(gTorAddr->sa_data, preppedAddr->ai_addr->sa_data, SA_DATA_BC); 
  
  /* Freeze the memory pointed to by gTorSockAddr such that any attempts to
   * overwrite it will immediately segfault, this coupled with the SECCOMP
   * rules initialized later on to force connect() to use only this struct,
   * this is in furtherance of preventing proxy bypass attacks
   */
  if( !freezeMemoryPane(gTorAddr, sizeof(struct sockaddr)) ){
    logErr("Failed to freeze the memory pane of global tor sockaddr");
    return 0; 
  }
  
  /* Free the memory allocated by getaddrinfo */ 
  freeaddrinfo(preppedAddr);
  
  return 1;
}



/* seccompWl applies a SECCOMP whitelisting filter to the redirector process, 
 * such that attempts to use syscalls / parameters that haven't been whitelisted
 * results in an immediate segfault of the redirector process. 
 *
 * SECCOMP is used both for generally restricting the kernel attack surface 
 * present to the redirector process, as well as specifically for preventing 
 * proxy bypass attacks via restrictions on the networking syscalls (see code).
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

  /****************************NETWORKING SYSCALLS*****************************/ 

  /* Only allow sendto with NULL for dest_addr, 0 for addrlen. This prevents
   * this syscall from being used directly to transmit UDP traffic, hardening
   * from proxy bypass attacks. 
   */  
  ret |= seccomp_rule_add( filter, SCMP_ACT_ALLOW, 
                           SCMP_SYS(sendto), 2,  
                           SCMP_CMP( 4 , SCMP_CMP_EQ , 0), 
                           SCMP_CMP( 5 , SCMP_CMP_EQ , 0)
                         );

  /* Only allow recvfrom with NULL for src_addr, 0 for addrlen. We don't deal 
   * with UDP traffic and this may help to prevent some attacks on anonymity. 
   */   
  ret |= seccomp_rule_add( filter, SCMP_ACT_ALLOW, 
                           SCMP_SYS(recvfrom), 2,
                           SCMP_CMP( 4 , SCMP_CMP_EQ , 0), 
                           SCMP_CMP( 5 , SCMP_CMP_EQ , 0)
                         );

  /* Only allow the socket syscall with:
   *
   * Domain:
   *   AF_INET domain for ipv4 (used for connecting to Tor SocksPort)
   *   AF_UNIX domain for Unix Sockets (used for listening for child net NS) 
   *
   * Type:
   *   SOCK_STREAM (typically only TCP, definitely not UDP)
   *
   * Protocol: 
   *   0, which is default, and all we should ever need to allow.
   */ 
  ret |= seccomp_rule_add( filter, SCMP_ACT_ALLOW, 
                           SCMP_SYS(socket), 3, 
                           SCMP_CMP( 0 , SCMP_CMP_EQ , AF_INET),
                           SCMP_CMP( 1 , SCMP_CMP_EQ , SOCK_STREAM),
                           SCMP_CMP( 2 , SCMP_CMP_EQ , 0)
                         );

  ret |= seccomp_rule_add( filter, SCMP_ACT_ALLOW, 
                           SCMP_SYS(socket), 3, 
                           SCMP_CMP( 0 , SCMP_CMP_EQ , AF_UNIX),
                           SCMP_CMP( 1 , SCMP_CMP_EQ , SOCK_STREAM),
                           SCMP_CMP( 2 , SCMP_CMP_EQ , 0)
                         );

  /* Only allow connect with the static global struct addrinfo *gTorAddr,
   * the memory backing for which is set to read only with mprotect. This 
   * prevents using connect for anything other than connecting to the Tor
   * SocksPort, which prevents TCP proxy bypass attacks.
   *
   * Additionally, only allow with gTorLen, which compliments gTorAddr.
   */ 
   ret |= seccomp_rule_add( filter, SCMP_ACT_ALLOW, 
                            SCMP_SYS(connect), 2,
                            SCMP_CMP( 1 , SCMP_CMP_EQ, (scmp_datum_t)gTorAddr),
                            SCMP_CMP( 2 , SCMP_CMP_EQ, gTorLen)
                          ); 

  /* Poll is used for managing the sockets */
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(poll), 0);

  /*Bind is used for binding the Unix Domain Socket */
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(bind), 0);

  /* Listen is used for listening for connections from child net ns */          
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(listen), 0);

  /* Accept is used for accepting connections from child net ns */
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(accept), 0);

  /*******************************MEMORY SYSCALLS******************************/ 

  /* Allow mprotect unless it is trying to set memory as executable */ 
  ret |= seccomp_rule_add( filter, SCMP_ACT_ALLOW, 
                           SCMP_SYS(mprotect), 1,
                           SCMP_CMP( 2 , SCMP_CMP_NE , PROT_EXEC)
                         );

  /* These are required by the secAlloc and secFree functions */ 
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(mmap), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(munmap), 0);


  /********************************OTHER SYSCALLS******************************/ 

  /* Clone is used by fork, the fork syscall itself doesn't appear to be */ 
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(clone), 0);

  /* Unlink is used for removing any existing file with the name used for the
   * Unix Domain Socket.
   */ 
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(unlink), 0);
  
  /* These are required to exit */
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(exit_group), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(exit), 0);
  
  /* The logger back end requires flock and fstat */
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(flock), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(fstat), 0);


  /* These are (probably) required for various things, from using the logging 
   * system, to managing sockets. TODO look into these more.
   */ 
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(write), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(close), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(open), 0);
  ret |= seccomp_rule_add(filter, SCMP_ACT_ALLOW , SCMP_SYS(read), 0);




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
