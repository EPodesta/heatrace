#include "lib.h"

static struct element static_v[NUM_ELEM];

int main(int argc, char **argv) {
	struct element *heap_v = (struct element *) malloc (sizeof(struct element)*NUM_ELEM);
	struct element *heap_v2 = (struct element *) malloc (NUM_ELEM*sizeof(struct element));
	struct element *heap_calloc_v = (struct element *) calloc (NUM_ELEM, sizeof(struct element));
	struct element stack_v[NUM_ELEM];

	// fazer um loop sem otimizacoes para verificar o static data. Sem acessos
	// nem nada.
	for (int i = 0; i < NUM_ELEM; i++)
		for (int j = 0; j< (i+1)*100; j++) {
			static_v[i].value = i;
			heap_v[i].value = i;
			heap_v2[i].value = i;
			heap_calloc_v[i].value = i;
			stack_v[i].value = i;
		}

	// struct element *heap_realloc_v = (struct element *) malloc (NUM_ELEM*sizeof(struct element));
	struct element *heap_realloc_v = (struct element *) realloc (heap_calloc_v, sizeof(struct element)*(NUM_ELEM/2));
	for (int i = 0; i < NUM_ELEM/2; i++)
		for (int j = 0; j< (i+1)*100; j++) {
			heap_realloc_v[i].value = i;
		}

	printf("Heap V: %p \n", heap_v);
	printf("Heap V2: %p \n", heap_v2);
	printf("Heap Calloc: %p \n", heap_calloc_v);
	printf("Heap Realloc: %p \n", heap_realloc_v);
	printf("Stack V: %p \n", stack_v);
	free(heap_v);
	free(heap_v2);
	// free(heap_calloc_v);
	free(heap_realloc_v);

	return 0;
}
