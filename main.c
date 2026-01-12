#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
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

void initHeap()
{
	void *start = mmap(NULL, getpagesize(), PROT_WRITE | PROT_READ,
	                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (start == MAP_FAILED)
	{
		perror("Map failed");
		exit(1);
	}

	struct block_header *header = (struct block_header *)start;

	header->size = getpagesize() - sizeof(struct block_header);
	header->is_free = true;
	header->magic = BLOCK_MAGIC;

	header->prev = NULL;
	header->next = NULL;

	free_list = header;
}

void *_malloc(size_t length)
{
	if (!free_list)
		initHeap();

	// align the length
	length = ALIGN(length);

	if (free_list->size < length)
		printf("TODO: Create another page or smthng\n");

	struct block_header *current = free_list;

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
		if (remaining >= sizeof(struct block_header) + MIN_HEADER_SIZE)
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

			new_block->size = remaining - sizeof(block_header);
			current->size = length;
		}

		break;
	}

	if (!current)
	{
		fprintf(stdout, "No space found");
		return NULL;
	}

	// return pointer to data section (skip the header)
	return (void *)(current + 1);
}

void coalesce(struct block_header *header)
{
	// merge with next header
	if (header->next && header->next->is_free)
	{
		struct block_header *next = header->next;

		header->size += next->size + sizeof(struct block_header);
		header->next = next->next;

		if (header->next)
			header->next->prev = header;
	}

	// merge with prev header
	if (header->prev && header->prev->is_free)
	{
		struct block_header *prev = header->prev;

		prev->size += header->size + sizeof(struct block_header);
		prev->next = header->next;

		if (prev->next)
			prev->next->prev = prev;
	}
}

//
// TODO: handle cases to free pointers in the middle of the array or
// data section
// TODO: Merge with adjacent free blocks
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

int main()
{
	printf("=== Testing coalescing ===\n");
	printf("Page size: %d\n", getpagesize());

	// Allocate 3 adjacent blocks
	void *p1 = _malloc(64);
	void *p2 = _malloc(64);
	void *p3 = _malloc(64);

	printf("Allocated:\n");
	printf("  p1=%p\n", p1);
	printf("  p2=%p\n", p2);
	printf("  p3=%p\n", p3);

	// Free middle block
	_free(p2);
	printf("\nFreed p2\n");

	// Free first block - should merge with p2
	_free(p1);
	printf("Freed p1 (should merge with p2)\n");

	// Now allocate 150 bytes - should fit in merged block
	void *p4 = _malloc(150);
	printf("\nAllocated p4=%p (150 bytes)\n", p4);

	if (p4 == p1)
	{
		printf("✓ SUCCESS: Coalescing works! p4 reused merged p1+p2 block\n");
	}
	else
	{
		printf("✗ FAIL: p4=%p, p1=%p - blocks didn't merge\n", p4, p1);
	}

	// Test full coalescing
	_free(p3);
	_free(p4);
	printf("\nFreed p3 and p4 - all blocks should merge\n");

	// Should be able to allocate almost the entire page now
	void *big = _malloc(3800);
	if (big)
	{
		printf("✓ SUCCESS: Allocated 3800 bytes after full coalesce\n");
	}
	else
	{
		printf("✗ FAIL: Couldn't allocate 3800 bytes\n");
	}
}
