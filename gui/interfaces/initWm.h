#pragma once

/* initWm initializes the window manager, and then it initializes the GUI by 
 * dereferencing the pointer to the initGui function
 */ 

int initWm(int (*initGui)(void));
