#include <FL/Fl.H>
#include <FL/Fl_Window.H>
#include <FL/Fl_Box.H>
#include <FL/Fl_Button.H> 

#include "initGui.h"



/* GUI Prototypes */
static void startWindow(void);
static int resize(int a);



/* Globals */
static Fl_Window *window;





int initGui(void) 
{
  /* Add a handler for when the screen is resized */ 
  Fl::add_handler(resize); 	
  
  /* Initiate the GUI window */
  startWindow();
  
  /* Loop waiting for events */ 
  return Fl::run();
}



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
  
  /* Return signal indicating that we handled the screen size changing event */ 
  return FL_SCREEN_CONFIGURATION_CHANGED;
}
