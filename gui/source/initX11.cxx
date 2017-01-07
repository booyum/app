#include <X11/Xlib.h>
#include <X11/extensions/Xrandr.h>
#include <X11/cursorfont.h> 
#include <stdio.h> 

#include <stdlib.h>
#include <unistd.h> 

#include "initX11.h"


extern "C"{
  #include "isolFs.h"
  #include "logger.h"
}

static void loopX(Display *dpy, Window root, int randrBase);


int initX11(int (*initGui)(void))
{
  Display *dpy;
  Window  root;
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
    logErr("Failed to initialize x11 randr");
    return 0;
  }
  
  /* Initialize the root window of the display */ 
  root = DefaultRootWindow(dpy);
  
  /* Register RRScreenChangeNotify Event on root window of display,
   * such that we receive this event on resolution changes (resizes) 
   */ 
  XRRSelectInput(dpy, root, RRScreenChangeNotifyMask);
  
  /* Fork so we can start both the window manager and the GUI, neither of which
   * return
   */
  switch(fork()){
    case -1:
      logErr("Forking to split GUI and WM failed");
      return 0; 
    case 0:
      loopX(dpy, root, randrBase); /* never returns */
      logErr("Failed to initialize the window manager"); 
      exit(-1); 
    default:
      initGui(); /* never returns */ 
      logErr("Failed to initialize the GUI");
      return 0; 
  }
  
  /* We should never actually return */ 
  return 0; 
}   


static void loopX(Display *dpy, Window root, int randrBase)
{
  XEvent event; 
  
  /* Isolate the x display from the filesystem */ 
  if( !isolFs("gui_sandbox", INIT_FSNS) ){
    logErr("Failed to isolate the window manager from the filesystem");
    return; 
  }
  
//  if( !isolKern() ){
//    logErr("Failed to isolate GUI from Kernel");
//    return; 
//  }
  //TODO isol kern here
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
