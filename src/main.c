#include "mem.h"
#include "test.h"

int main(int argc, char *argv[])
{
	setvbuf(stdout, NULL, _IONBF, 0);

	size_t page_size = sysconf(_SC_PAGESIZE);
	printf("Page size: %zu\n", page_size);

	printf("sizeof(block_header) = %zu\n", sizeof(block_header));
	printf("ALIGNED_BLOCK_SIZE = %zu\n", ALIGNED_BLOCK_SIZE);

	/* comprehensive_test(); */
	_malloc(10000000);

	return EXIT_SUCCESS;
}
