#include <stdint.h>
#include <cstdlib>
#include <cstdio>
#include "lib.h"
#define NUM_ELEM 200

int main(int argc, char **argv) {

	for (int i = 0; i < NUM_ELEM; i++)
		for (int j = 0; j< (i+1)*100; j++);

	return 0;
}
