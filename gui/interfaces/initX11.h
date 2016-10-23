#pragma once

/* initX11 initializes the window manager, and then it initializes the GUI by 
 * dereferencing the pointer to the initGui function
 */ 

int initX11(int (*initGui)(void));
