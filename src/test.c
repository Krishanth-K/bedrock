#include "test.h"
#include "mem.h"

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

void stress_test(void)
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
	for (int i = 0; i < 100; i++)
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
