#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sched.h>

#include "initIsolWin.h" 
#include "initWm.h"
#include "initGui.h"
#include "contPortCon.h" 
#include "isolNet.h" 
#include "isolName.h"
#include "isolIpc.h" 
#include "isolKern.h"



/* Simple bootstrapper to initialize the window manager and GUI */ 

/* Enums for the positions of argv */
enum{ CONT_PORT_TOKEN = 1 }; 

/* For extern */ 
static int gControlSocket = -1; 

int main(int argc, char *argv[])
{
  
  if( argc != 2 ){
    printf("Error: Wrong number of arguments passed to the GUI main\n");
    return -1; 
  }
  
  /* The isolated window, window manager, and GUI, do not need networking */ 
  if( !isolNet() ){
    printf("Error: Failed to isolate from the network\n"); 
    return -1; 
  }
  
  /* We don't need access to any system names either */ 
  if( !isolName() ){
    printf("Error: Failed to isolate from names\n");
    return -1;
  }
  
  /* Bring up the isolated Window */
  if( !initIsolWin() ){
    printf("Error: Failed to bring up an isolated window\n");
    return -1; 
  }
  
  /* Allow the isolated window to use IPC, on Linux this allows to use MIT-SHM, 
   * without which the GUI is very glitchy. 
   */ 
  if( !isolIpc() ){
    printf("Error: Failed to isolate from IPC\n");
    return -1; 
  }
  
  /* Currently taking on faith that token is correct size TODO */ 
  
  /* Make the control port connection */
  gControlSocket = initContPortCon( argv[CONT_PORT_TOKEN] );
  if( gControlSocket == - 1){
    printf("Error: Failed to get control socket\n");
    return -1; 
  } 
  
  /* Initialize the window manager and GUI */ 
  if( !initWm(&initGui) ){
    printf("Error: Failed to initialize the GUI\n");
    return -1; 
  }
  
  return 0; /* initWm should never return */ 
}




