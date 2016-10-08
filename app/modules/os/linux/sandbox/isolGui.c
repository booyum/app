#include <unistd.h>
#include <stdlib.h>

#include "isolGui.h"
#include "logger.h" 

int isolGui(void)
{
  char *guiCmd[] = {"guiBin", NULL};
  
  switch( fork() ){
    /* There was an error forking */ 
    case -1:{
      logErr("Forking to isolated GUI failed");
      return 0;
    }
    
    /* Child initializes the isolated GUI */
    case 0:{
       if( execve("bins/guiBin", guiCmd, NULL) == -1 ){ //TODO pass a control port cookie as an environment variable
         logErr("Failed to execve the GUI");
         exit(-1);
       }
    }
  
    /* Parent breaks and returns success */ 
    default:{
      break;
    }
  }
  
  return 1;
}
