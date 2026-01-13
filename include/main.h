#pragma once
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

extern const int MIN_HEADER_SIZE;
extern const size_t BLOCK_MAGIC;

// header with metadata for the memory block
typedef struct block_header
{
	size_t size;
	bool is_free;
	size_t magic;

	struct block_header *prev;
	struct block_header *next;

} block_header;

extern const size_t ALIGNED_BLOCK_SIZE;

// create a new page and initialize a header and return it
struct block_header *getHeap();

void initHeap();
void expandHeap();

void coalesce(struct block_header *current);

void validate_list();

void *_malloc(size_t length);
void _free(void *data);
void *_calloc(size_t num, size_t size);
void *_realloc(void *ptr, size_t size);
