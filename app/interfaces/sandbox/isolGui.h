#pragma once

/* isolGui shall instantiate the isolated GUI, which typically will include 
 * an isolating display server such as Xephyr for X11, a basic window manager 
 * controller, as well as the actual GUI. 
 */ 

int isolGui(void);
