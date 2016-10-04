#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sched.h>

#include "initIsolWin.h" 
#include "initWm.h"
#include "initGui.h"

#include "isolNet.h" 
#include "isolName.h"
#include "isolIpc.h" 
#include "isolKern.h"


/* Simple bootstrapper to initialize the window manager and GUI */ 
int main()
{
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
  
  /* Don't need IPC (on Linux this prevents Xephyr from using mit-shm)*/
  if( !isolIpc() ){
    printf("Error: Failed to isolate from IPC\n");
    return -1; 
  }
  
  /* Bring up the isolated Window */
  if( !initIsolWin() ){
    printf("Error: Failed to bring up an isolated window\n");
    return -1; 
  }
  
  /* Initialize window manager and GUI Kernel isolation */ 
  if( !isolKern() ){
    printf("Error: Failed to isolate GUI from Kernel\n");
    return -1; 
  }
  
  /* Initialize the window manager and GUI */ 
  if( !initWm(&initGui) ){
    printf("Error: Failed to initialize the GUI\n");
    return -1; 
  }
  
  return 0; //never make it here
}




