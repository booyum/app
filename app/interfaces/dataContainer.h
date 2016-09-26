#pragma once
#include <stdint.h>

typedef struct dataContainerObject{
  void   *data;
  size_t bytesize;
  int (*destroy)(struct dataContainerObject** thisPointer);
}dataContainerObject;

dataContainerObject *newDataContainer(size_t bytesize);