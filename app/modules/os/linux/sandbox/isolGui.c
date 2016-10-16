#include <unistd.h>
#include <stdlib.h>

#include "isolGui.h"
#include "logger.h" 

int isolGui(const char *contPortToken)
{
  char *guiCmd[] = {"guiBin", contPortToken, NULL};
  
  if( contPortToken == NULL ){
    logErr("Something was NULL that shouldn't have been");
    return 0; 
  }
  
  switch( fork() ){
    /* There was an error forking */ 
    case -1:{
      logErr("Forking to isolated GUI failed");
      return 0;
    }
    
    /* Child initializes the isolated GUI */
    case 0:{
       if( execve("bins/guiBin", guiCmd, NULL) == -1 ){ 
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
