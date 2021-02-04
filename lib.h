#include <stdint.h>
#include <cstdlib>
#include <cstdio>

#define NUM_ELEM 200

struct element {
	uint32_t _[1023]; //padding
	uint32_t value;
};

extern void main2(void);
