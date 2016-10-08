#include <X11/Xlib.h>
#include <X11/extensions/Xrandr.h>
#include <X11/cursorfont.h> 
#include <stdio.h> 

#include <stdlib.h>
#include <unistd.h> 

#include "initWm.h"
#include "isolFs.h"
#include "isolKern.h"

static void loopX(Display *dpy, Window root, int randrBase);


int initWm(int (*initGui)(void))
{
  Display *dpy;
  Window  root;
  Cursor  cursor; 
  int     randrBase;
  int     err;
  int     major;
  int     minor; 
  
  /* Poll opening the display until a connection is established */ 
  do{
    dpy = XOpenDisplay(0X0);
  }while(!dpy); 
  
  
  /* Make sure the display supports randr, initialize the randr base codes */ 
  if(!XRRQueryExtension(dpy, &randrBase, &err) || !XRRQueryVersion(dpy, &major, &minor) ){
    printf("Failed to initialize x11 randr");
    return 0;
  }
  
  /* Initialize the root window of the display */ 
  root = DefaultRootWindow(dpy);
  
  /* Initialize a cursor */
  try{ 
    cursor = XCreateFontCursor(dpy, 2);
  }
  catch(...){
    printf("Error: Initializing a cursor for the window threw an exception\n");
    return 0; 
  }
  /* Use the initialized cursor for the root window of the display */ 
  try{
    XDefineCursor(dpy, root, cursor);
  }
  catch(...){
    printf("Error: Associating a cursor with the window threw an exception\n");
    return 0; 
  }
  
  /* Register RRScreenChangeNotify Event on root window of display,
   * such that we receive this event on resolution changes (resizes) 
   */ 
  XRRSelectInput(dpy, root, RRScreenChangeNotifyMask);
  
  /* Fork so we can start both the window manager and the GUI, neither of which
   * return
   */
  switch(fork()){
    case -1:
      printf("Error: Forking to split GUI and WM failed\n");
      return 0; 
    case 0:
      loopX(dpy, root, randrBase); /* never returns */
      printf("Error: Failed to initialize the window manager\n"); 
      exit(-1); 
    default:
      initGui(); /* never returns */ 
      printf("Error: Failed to initialize the GUI\n");
      return 0; 
  }
  
  /* We should never actually return */ 
  return 0; 
}   


static void loopX(Display *dpy, Window root, int randrBase)
{
  XEvent event; 
  
  /* Isolate the x display from the filesystem */ 
  if( !isolFs(INIT_FSNS) ){
    printf("Error: Failed to isolate the window manager from the filesystem\n");
    return; 
  }
  
  if( !isolKern() ){
    printf("Error: Failed to isolate GUI from Kernel\n");
    return; 
  }
  
  /* Loop waiting for X11 events */ 
  while(1){
    XNextEvent(dpy, &event);
    
    /* The screen size of the display has changed */ 
    if(event.type == RRScreenChangeNotify + randrBase){
      /* Required after RRScreenChangeNotify as per xrandr documentation */
      XRRUpdateConfiguration(&event);
      /* Causes the GUI to actually update its perception of the screen size */ 
      XRRGetScreenInfo(dpy, root);
    }
    
  }
}
