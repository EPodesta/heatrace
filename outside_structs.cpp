#include "lib.h"

static struct element static_v2[NUM_ELEM];

void main2(void) {
	struct element *heap_v2 = (struct element *) malloc (sizeof(struct element)*NUM_ELEM);
	struct element stack_v2[NUM_ELEM];

	for (int i = 0; i < NUM_ELEM; i++)
		for (int j = 0; j< (i+1)*100; j++) {
			static_v2[i].value = i;
			heap_v2[i].value = i;
			stack_v2[i].value = i;
		}

	free(heap_v2);
}
