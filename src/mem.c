#include "mem.h"
#include "test.h"
#include <stddef.h>
#include <unistd.h>

#define ALIGNMENT 8
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))

struct block_header *block_list = NULL;
struct block_header *free_list = NULL;

const int MIN_HEADER_SIZE = 8;
const size_t BLOCK_MAGIC = 0xDEADBEEF;
const size_t ALIGNED_BLOCK_SIZE = ALIGN(sizeof(struct block_header));

// Helper: Insert block at the head of the free list
void addToFreeList(struct block_header *block)
{
	if (!block->is_free)
	{
		fprintf(stderr, "[ERROR] addToFreeList called on allocated block\n");
		return;
	}

	block->next_free = free_list;
	block->prev_free = NULL;

	if (free_list)
	{
		free_list->prev_free = block;
	}

	free_list = block;
}

// Helper: Remove block from the free list
void removeFromFreeList(struct block_header *block)
{
	if (!block)
		return;

	if (block->prev_free)
	{
		block->prev_free->next_free = block->next_free;
	}
	else
	{
		free_list = block->next_free;
	}

	if (block->next_free)
	{
		block->next_free->prev_free = block->prev_free;
	}

	block->next_free = NULL;
	block->prev_free = NULL;
}

// create a new page and initialize a header and return it
struct block_header *getHeap(size_t size)
{
	size_t page_size = sysconf(_SC_PAGESIZE);

	size_t required = size + ALIGNED_BLOCK_SIZE;
	int num_pages = (required + page_size - 1) / page_size;
	size_t total_size = num_pages * page_size;

	void *start = mmap(NULL, total_size, PROT_WRITE | PROT_READ,
	                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	// printf("DEBUG: mmap returned %p\n", start);

	if (start == MAP_FAILED)
	{
		perror("Map failed");
		exit(1);
	}

	struct block_header *header = (struct block_header *)start;

	header->size = total_size - ALIGNED_BLOCK_SIZE;
	header->is_free = true;
	header->magic = BLOCK_MAGIC;

	header->prev = NULL;
	header->next = NULL;

	// Initialize free pointers but don't add to list yet (caller does it)
	header->next_free = NULL;
	header->prev_free = NULL;

	return header;
}

void initHeap(void)
{
	size_t page_size = sysconf(_SC_PAGESIZE);
	struct block_header *header = getHeap(page_size);
	block_list = header;

	// Add initial block to free list
	addToFreeList(header);
}

void coalesce(struct block_header *current)
{
	// MERGE WITH NEXT
	// Check if the next block exists, is free, and is physically adjacent
	if (current->next && current->next->is_free &&
	    (char *)current + ALIGNED_BLOCK_SIZE + current->size ==
	        (char *)current->next)
	{
		struct block_header *next_block = current->next;

		// IMPORTANT: Remove the absorbed block from the free list first
		removeFromFreeList(next_block);

		current->size += next_block->size + ALIGNED_BLOCK_SIZE;
		current->next = next_block->next;

		if (next_block->next)
			next_block->next->prev = current;

		// next_block is now garbage
	}

	// MERGE WITH PREV
	// Check if the prev block exists, is free, and is physically adjacent
	if (current->prev && current->prev->is_free &&
	    (char *)current->prev + ALIGNED_BLOCK_SIZE + current->prev->size ==
	        (char *)current)
	{
		struct block_header *prev_block = current->prev;

		// IMPORTANT: Remove the absorbed block (current) from the free list
		removeFromFreeList(current);

		prev_block->size += current->size + ALIGNED_BLOCK_SIZE;
		prev_block->next = current->next;

		if (current->next)
			current->next->prev = prev_block;

		// current is now garbage, we should return the merged block if needed
		// but since we don't return anything, it's fine.
	}
}

void validate_list(void)
{
	struct block_header *walk = block_list;
	int count = 0;
	while (walk)
	{
		if (walk->magic != BLOCK_MAGIC)
		{
			printf("[ERROR] Corrupted block at %p, magic=%zx\n", (void *)walk,
			       walk->magic);
			abort();
		}
		walk = walk->next;
		count++;
	}
	// printf("List validated: %d blocks\n\n", count);
}

void expandHeap(size_t min_size)
{
	// find the last block in the physical list
	struct block_header *current = block_list;

	if (!block_list)
	{
		initHeap();
		return;
	}

	while (current->next)
		current = current->next;

	struct block_header *new_page_block = getHeap(min_size);

	// attach the last block with the new page block
	current->next = new_page_block;
	new_page_block->prev = current;

	// Add new block to free list
	addToFreeList(new_page_block);

	// Try to coalesce with the previous block (which is 'current')
	// if 'current' was free, they will merge.
	// We call coalesce on the *left* block essentially, or we can call it on
	// new_page_block simpler to call on new_page_block and let it merge left.
	coalesce(new_page_block);

	// validate_list();
}

void *_malloc(size_t length)
{
	if (!block_list)
		initHeap();

	// align the length
	length = ALIGN(length);

	struct block_header *current = free_list;

	while (current)
	{
		// skip if cant allocate in this block
		if (current->size < length)
		{
			current = current->next_free;
			continue;
		}

		// allocate memory
		current->is_free = false;

		// IMPORTANT: Remove from free list first
		removeFromFreeList(current);

		// split block logic
		size_t remaining = current->size - length;
		if (remaining >= ALIGNED_BLOCK_SIZE + MIN_HEADER_SIZE)
		{
			// get pointer to data area (right after the header)
			void *data_start = (void *)(current + 1);

			// create the new header for the split part
			struct block_header *new_block =
			    (struct block_header *)((char *)data_start + length);

			// Update physical links
			new_block->next = current->next;
			current->next = new_block;

			new_block->prev = current;
			if (new_block->next)
				new_block->next->prev = new_block;

			// Setup new block
			new_block->is_free = true;
			new_block->magic = BLOCK_MAGIC;
			new_block->size = remaining - ALIGNED_BLOCK_SIZE;
			current->size = length;

			// Add new block to free list
			addToFreeList(new_block);
		}

		// return pointer to data section (skip the header)
		return (void *)(current + 1);
	}

	// if no space found, expand heap and try again recursively
	expandHeap(length);
	return _malloc(length);
}

void _free(void *data)
{
	if (!data)
		return;

	// 1. alignment check: Pointers from malloc are always aligned.
	if (((size_t)data & (ALIGNMENT - 1)) != 0)
	{
		fprintf(stderr,
		        "[ERROR]: Unaligned pointer %p passed to free (points to "
		        "middle of block?)\n",
		        data);
		abort();
	}

	struct block_header *current = (struct block_header *)data - 1;

	// 2. magic number check: The header magic must match.
	if (current->magic != BLOCK_MAGIC)
	{
		fprintf(stderr, "[ERROR]: Invalid pointer or corrupted block\n");
		abort();
	}

	if (current->is_free)
	{
		fprintf(stderr, "[WARN]: Double free detected\n");
		return;
	}

	current->is_free = true;

	// Add to free list (LIFO)
	addToFreeList(current);

	// Coalesce physically
	coalesce(current);
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
