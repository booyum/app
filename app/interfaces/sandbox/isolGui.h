#pragma once

/* isolGui shall instantiate the isolated GUI, which typically will include 
 * an isolating display server such as Xephyr for X11, a basic window manager 
 * controller, as well as the actual GUI. 
 *
 * isolGui is passed a pointer to heap allocated memory holding the control 
 * port token, the control port token is always 256 bytes of randomness, this
 * will be passed to the GUI during instantation and used such that it can 
 * connect to the control port. 
 */ 

int isolGui(const char *contPortToken);
