#include "lib.h"

static struct element static_v[NUM_ELEM];

int main(int argc, char **argv) {
	struct element *heap_v = (struct element *) malloc (sizeof(struct element)*NUM_ELEM);
	struct element stack_v[NUM_ELEM];

	for (int i = 0; i < NUM_ELEM; i++)
		for (int j = 0; j< (i+1)*100; j++) {
			static_v[i].value = i;
			heap_v[i].value = i;
			stack_v[i].value = i;
		}

	free(heap_v);

	main2();

	return 0;
}
