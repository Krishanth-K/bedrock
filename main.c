#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define ALIGNMENT 8
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))

// PERF: Now all blocks are in the linked list, not only free ones

struct block_header *free_list = NULL;
const int MIN_HEADER_SIZE = 8;
const size_t BLOCK_MAGIC = 0xDEADBEEF;

// header with metadata for the memory block
typedef struct block_header
{
	size_t size;
	bool is_free;
	size_t magic;

	struct block_header *prev;
	struct block_header *next;

} block_header;

const size_t ALIGNED_BLOCK_SIZE = ALIGN(sizeof(struct block_header));

// create a new page and initialize a header and return it
struct block_header *getHeap()
{
	void *start = mmap(NULL, getpagesize(), PROT_WRITE | PROT_READ,
	                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (start == MAP_FAILED)
	{
		perror("Map failed");
		exit(1);
	}

	struct block_header *header = (struct block_header *)start;

	header->size = getpagesize() - ALIGNED_BLOCK_SIZE;
	header->is_free = true;
	header->magic = BLOCK_MAGIC;

	header->prev = NULL;
	header->next = NULL;

	return header;
}

void initHeap()
{
	struct block_header *header = getHeap();
	free_list = header;
}

void coalesce(struct block_header *current)
{

	// merge with next header
	//
	// Check if the two blocks are adjacent in memory before combining them
	//
	if (current->next && current->next->is_free &&
	    (char *)current + ALIGNED_BLOCK_SIZE + current->size ==
	        (char *)current->next)
	{
		struct block_header *next_block = current->next;

		current->size += next_block->size + ALIGNED_BLOCK_SIZE;
		current->next = next_block->next;

		if (next_block->next)
			next_block->next->prev = current;
	}

	// merge with prev header
	//
	// Check if the two blocks are adjacent in memory before combining them
	//
	if (current->prev && current->prev->is_free &&
	    (char *)current->prev + ALIGNED_BLOCK_SIZE + current->prev->size ==
	        (char *)current)
	{
		struct block_header *prev = current->prev;

		prev->size += current->size + ALIGNED_BLOCK_SIZE;
		prev->next = current->next;

		if (current->next)
			current->next->prev = prev;

		// now current points to garbage inside the combined data section
	}
}

void validate_list()
{
	struct block_header *walk = free_list;
	int count = 0;
	while (walk)
	{
		if (walk->magic != BLOCK_MAGIC)
		{
			printf("[ERROR] Corrupted block at %p, magic=%zx\n", walk,
			       walk->magic);
			abort();
		}

		/* printf("Block %d: %p, size=%zu, free=%d, next=%p, prev=%p\n", count,
		 */
		/*        walk, walk->size, walk->is_free, walk->next, walk->prev); */

		walk = walk->next;
		count++;
		if (count > 10000)
		{
			printf("[ERROR] Circular list at block %p!\n", walk);
			abort();
		}
	}
	printf("List validated: %d blocks\n\n", count);
}
void expandHeap()
{
	struct block_header *new_page_block = getHeap();

	// find the last block in the free list
	struct block_header *current = free_list;

	if (!free_list)
	{
		free_list = new_page_block;
		return;
	}

	while (current->next)
		current = current->next;

	// attach the last block with the new page block
	current->next = new_page_block;
	new_page_block->prev = current;

	// coalesce them if possible
	if (current->is_free)
		coalesce(current);

	validate_list();
}

void *_malloc(size_t length)
{
	if (!free_list)
		initHeap();

	// align the length
	length = ALIGN(length);

	struct block_header *current = free_list;
	int iter = 0;

	while (current)
	{
		// skip if cant allocate in this block
		if (current->size < length || !current->is_free)
		{
			current = current->next;
			continue;
		}

		// allocate memory
		current->is_free = false;

		// if there is more space for the next header, place it, or dont
		size_t remaining = current->size - length;
		if (remaining >= ALIGNED_BLOCK_SIZE + MIN_HEADER_SIZE)
		{
			// get pointer to data area (right after the header)
			// temp + 1 skips a sizeof(block_header) as temp is a block_header*
			void *data_start = (void *)(current + 1);

			// skip length bytes and then create the new header there
			struct block_header *new_block =
			    (struct block_header *)((char *)data_start + length);

			// FIX: update the next_free_block pointer of temp's parent
			new_block->next = current->next;
			current->next = new_block;

			// update the prev pointers
			new_block->prev = current;
			if (new_block->next)
				new_block->next->prev = new_block;

			new_block->is_free = true;
			new_block->magic = BLOCK_MAGIC;

			new_block->size = remaining - ALIGNED_BLOCK_SIZE;
			current->size = length;
		}

		break;
	}

	// if no space in current page, create a new page and then allocate
	if (!current)
	{
		expandHeap();
		return _malloc(length);
	}

	// return pointer to data section (skip the header)
	return (void *)(current + 1);
}

//
// TODO: handle cases to free pointers in the middle of the array or
// data section
void _free(void *data)
{
	if (!data)
		return;

	struct block_header *header = (struct block_header *)data - 1;

	if (header->magic != BLOCK_MAGIC)
	{
		fprintf(stderr, "[ERROR]: Invalid pointer or corrupted block\n");
		abort();
	}

	if (header->is_free)
	{
		fprintf(stderr, "[WARN]: Double free detected\n");
		return;
	}

	header->is_free = true;

	coalesce(header);
}

void *_calloc(size_t num, size_t size)
{
	size_t total = num * size;

	// check for overflow
	if (num != 0 && total / num != size)
	{
		fprintf(stderr, "[ERROR]: Integer overflow during calloc\n");
		return NULL;
	}

	// initialize the memory
	void *data = _malloc(total);

	if (!data)
	{
		fprintf(stderr, "[ERROR]: _malloc failed!\n");
		return NULL;
	}

	// set initial values to 0
	memset(data, 0, total);

	return data;
}

// create a new space in memory for "size" bytes and then copy the content
// over from "ptr"
void *_realloc(void *ptr, size_t size)
{
	size = ALIGN(size);

	// explicitly allowed
	if (!ptr)
		return _malloc(size);

	// a valid pointer and a size == 0 is equivalent to free(ptr)
	if (size == 0)
	{
		_free(ptr);
		return NULL;
	}

	struct block_header *block = (struct block_header *)ptr - 1;
	size_t current_size = block->size;

	// check if the pointer can be realloc'ed
	if (block->magic != BLOCK_MAGIC)
	{
		fprintf(stderr, "[ERROR]: Invalid pointer\n");
		return NULL;
	}

	// if current block is big enough, return it
	if (current_size > size)
		return ptr;

	// allocate the space and verify if it worked
	void *new_ptr = _malloc(size);
	if (!new_ptr)
	{
		fprintf(stderr, "[ERROR]: _malloc failed!\n");
		return NULL;
	}

	// copy the contents from ptr to new_ptr
	size_t min_size = current_size < size ? current_size : size;
	memcpy(new_ptr, ptr, min_size);

	// free the original memory
	_free(ptr);

	return new_ptr;
}

void verify_pointer(void *ptr, size_t size, char pattern)
{
	char *chk = (char *)ptr;
	for (size_t i = 0; i < size; i++)
	{
		if (chk[i] != pattern)
		{
			printf("[ERROR] Data corruption at %p+%zu. Expected %x, got %x\n",
			       ptr, i, pattern, chk[i]);
			abort();
		}
	}
}

void stress_test()
{
	printf("=== Starting Harsher Stress Test ===\n");
	srand(42); // Fixed seed for reproducibility

	const int NUM_POINTERS = 1000;
	void *ptrs[NUM_POINTERS];
	size_t sizes[NUM_POINTERS];
	bool active[NUM_POINTERS]; // Track if ptrs[i] is currently allocated

	memset(ptrs, 0, sizeof(ptrs));
	memset(active, 0, sizeof(active));

	// Test 1: Random Allocations & Frees with Data Verification
	printf("[1/3] Running Random Operations check...\n");
	for (int i = 0; i < 10000; i++)
	{
		int idx = rand() % NUM_POINTERS;

		if (active[idx])
		{
			// Verify data before freeing
			verify_pointer(ptrs[idx], sizes[idx], (char)(idx & 0xFF));
			_free(ptrs[idx]);
			active[idx] = false;
		}
		else
		{
			// Allocate random size: mix of small and large
			size_t size = (rand() % 1024) + 1; // Small
			if (rand() % 10 == 0)
				size += (rand() % 10) * 4096; // Occasional large pages

			void *p = _malloc(size);
			if (!p)
			{
				printf("[ERROR] Allocation failed at iteration %d\n", i);
				abort();
			}

			// Fill with pattern
			memset(p, (char)(idx & 0xFF), size);

			ptrs[idx] = p;
			sizes[idx] = size;
			active[idx] = true;
		}

		if (i % 1000 == 0)
			printf("  Iteration %d...\n", i);
	}
	printf("  Random operations passed.\n");

	// Clean up
	for (int i = 0; i < NUM_POINTERS; i++)
	{
		if (active[i])
		{
			verify_pointer(ptrs[i], sizes[i], (char)(i & 0xFF));
			_free(ptrs[i]);
		}
	}

	// Test 2: High Fragmentation Recovery
	printf("[2/3] Running Fragmentation Recovery check...\n");
	// Fill array
	for (int i = 0; i < 100; i++)
	{
		ptrs[i] = _malloc(128);
	}
	// Free every other one
	for (int i = 0; i < 100; i += 2)
	{
		_free(ptrs[i]);
	}
	// Allocate large block that requires coalescing
	void *big_chunk = _malloc(5000); // Should trigger coalescing or new page
	printf("  Allocated big chunk: %p\n", big_chunk);
	_free(big_chunk);

	// Free remaining
	for (int i = 1; i < 100; i += 2)
	{
		_free(ptrs[i]);
	}

	printf("\n✓ Stress test passed successfully\n");
}

int main()
{
	setvbuf(stdout, NULL, _IONBF, 0);
	printf("Page size: %d\n", getpagesize());
	printf("sizeof(block_header) = %zu\n", sizeof(block_header));
	printf("ALIGNED_BLOCK_SIZE = %zu\n", ALIGNED_BLOCK_SIZE);

	stress_test();

	return 0;
}
