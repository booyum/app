#include <FL/Fl.H>
#include <FL/Fl_Window.H>
#include <FL/Fl_Box.H>
#include <FL/Fl_Button.H> 
#include <FL/Fl_Input.H>
#include <FL/Fl_Tabs.H>
#include <FL/Fl_Text_Buffer.H>
#include <FL/Fl_Text_Display.H>
#include <FL/Fl_Text_Editor.H>
#include <sched.h> 

#include <unistd.h>

#include "initGui.h"


extern "C"{
  #include "isolFs.h" 
  #include "logger.h"
}

/* GUI Prototypes */
static void startWindow(void);
static int resize(int a);



/* Globals */
static Fl_Window *window;





int initGui(void) 
{
  /* Add a handler for when the screen is resized */ 
  Fl::add_handler(resize); 	
  
  /* Initialize a new mount namespace */ 
  if( unshare(CLONE_NEWNS) ){
    logErr("Failed to unshare the filesystem");
    return 0;  
  } 
  
  /* Initiate the GUI window */
  startWindow();
  
  switch( fork() ){
  
    /* There was an error forking */
    case -1:{
      logErr("Failed to fork for GUI");
      exit(-1); 
    }
    
    /* The child initializes the kernel isolation for the GUI toolkit and then
     * it actually runs the GUI toolkit, which should never return 
     */
    case 0:{
//TODO isolate kernel here
//      if( !isolKern() ){
//        logErr("Failed to isolate GUI from kernel");
//        exit(-1);
//      }
//      
      Fl::run(); /* Never returns */
      exit(-1); 
    }
    
    /* The parent isolates the GUI toolkit from the filesystem, then ends */ 
    default:{
    
      sleep(1); 
      
      if( !isolFs("gui_sandbox", NO_INIT_FSNS) ){
        logErr("Failed to isolate the GUI from the filesystem");
        exit(-1);
      }
      
      exit(0); 
    }
  }
  
  return 0; 
}

Fl_Tabs *tabs;


static void startWindow(void)
{
  int x = 0;
  int y = 0;
  int w = 0;
  int h = 0;
  
  /* Create the GUI window */
  window = new Fl_Window(0, 0); 
  
  /* Determine the screen size of display 0 */
  Fl::screen_work_area(x, y, w, h, 0);
  
  /* Have the window take up the entire screen size */
  window->resize(x,y,w,h);
  
  
  

  
  Fl_Group *grp1;
   tabs = new Fl_Tabs(20, 20, w , h );
{
    grp1 = new Fl_Group(40,50,w - 10 ,h - 10  ,"Accounts");
    {
      Fl_Text_Buffer *buff = new Fl_Text_Buffer();
       Fl_Text_Editor *test = new Fl_Text_Editor(60, 70, 200, 400);
      test->buffer(buff); 
  
   Fl_Button *button = new Fl_Button(25, 35, 10, 10, "new");
   
  /* Note that button must take focus to force the mouse to work after 
   * mount namespace is later disconnected from the file system. This did
   * not work when done with inputs however, perhaps other widgets can be used
   * but if all else fails this works.
   */ 
 button->take_focus(); 
    }
    grp1->end();
}
tabs->end();
tabs->resizable(grp1); 

  window->default_cursor(FL_CURSOR_DEFAULT);
  /* Done adding widgets */ 
  window->end();
  

  /* Show the window */ 
  window->show();
  


  /* And we are done */ 
  return;
}



static int resize(int a)
{
  int x = 0;
  int y = 0;
  int w = 0;
  int h = 0;
  
  /* Determine the screen size of display 0 */
  Fl::screen_work_area (x, y, w, h, 0);
  
  /* Have the window take up the entire screen size */ 
  window->resize(x,y,w,h);
  
  tabs->resize(0, 0, w, h);
  
  /* Return signal indicating that we handled the screen size changing event */ 
  return FL_SCREEN_CONFIGURATION_CHANGED;
}
