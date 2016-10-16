#pragma once
#include <stdint.h>
#include <stdlib.h>

/************************POINTER SECURITY FUNCTIONS****************************/
void *allocMemoryPane(size_t bytesRequested);
int freezeMemoryPane(void *memoryPane, size_t bytesize);


/*******************ALLOCATION SECURITY FUNCTIONS******************************/
void *secAlloc(size_t bytesRequested);

/****************************CLEAR SECURITY FUNCTIONS**************************/ 
int secMemClear(volatile uint8_t *memoryPointer, size_t bytesize);

/***************************FREE SECURITY FUNCTIONS****************************/
int secFree(void **dataBuffer, size_t bytesize);

/***********************STRING SECURITY FUNCTIONS******************************/
char *secStrCpy(char *dst, char *src, size_t dstBytesize);
int sec16ConstCmp(unsigned char *x, unsigned char *y);
int sec32ConstCmp(unsigned char *x, unsigned char *y);
int dataIndependentCmp(unsigned char *x, unsigned char *y, int n);

/***********************INTEGER SECURITY FUNCTIONS*****************************/
int secto_cast_long2_sizet(long x);
int secto_cast_int2_sizet(int x);
int secto_sizet_add_nowrap(size_t x, size_t y);
int secto_sizet_mul_nowrap(size_t x, size_t y);
int secto_add_int(signed int x, signed int y);
int secto_add_uint(unsigned int x, unsigned int y);

/**************************SYSTEM SECURITY FUNCTIONS***************************/
int disableCoreDumps(void);

/* secClone */
pid_t secClone(int (*execFunct)(void *), int flags);





