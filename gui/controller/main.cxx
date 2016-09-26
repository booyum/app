#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include "initIsolWin.h" 
#include "initWm.h"
#include "initGui.h"

#include "isolNet.h" 
#include "isolKern.h"


/* Simple bootstrapper to initialize the window manager and GUI */ 
int main()
{
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




