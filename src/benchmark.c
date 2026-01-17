#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

// Include your allocator
#include "mem.h"

#define NUM_RUNS 1

#define ITERATIONS 100000
#define SMALL_SIZE 64
#define MEDIUM_SIZE 1024
#define LARGE_SIZE 8192

// Timing utility
typedef struct
{
	struct timeval start;
	struct timeval end;
} Timer;

void timer_start(Timer *t) { gettimeofday(&t->start, NULL); }

double timer_end(Timer *t)
{
	gettimeofday(&t->end, NULL);
	return (t->end.tv_sec - t->start.tv_sec) * 1000.0 +
	       (t->end.tv_usec - t->start.tv_usec) / 1000.0;
}

// Benchmark 1: Sequential small allocations
double bench_sequential_small(bool use_custom)
{
	Timer t;
	void *ptrs[10000];

	timer_start(&t);
	for (int i = 0; i < 10000; i++)
	{
		ptrs[i] = use_custom ? _malloc(SMALL_SIZE) : malloc(SMALL_SIZE);
	}
	for (int i = 0; i < 10000; i++)
	{
		use_custom ? _free(ptrs[i]) : free(ptrs[i]);
	}
	return timer_end(&t);
}

// Benchmark 2: Random allocation/deallocation
double bench_random_ops(bool use_custom)
{
	Timer t;
	void *ptrs[1000] = {0};
	srand(42);

	timer_start(&t);
	for (int i = 0; i < ITERATIONS; i++)
	{
		int idx = rand() % 1000;
		if (ptrs[idx])
		{
			use_custom ? _free(ptrs[idx]) : free(ptrs[idx]);
			ptrs[idx] = NULL;
		}
		else
		{
			size_t size = (rand() % 512) + 16;
			ptrs[idx] = use_custom ? _malloc(size) : malloc(size);
		}
	}

	// Cleanup
	for (int i = 0; i < 1000; i++)
	{
		if (ptrs[i])
		{
			use_custom ? _free(ptrs[i]) : free(ptrs[i]);
		}
	}
	return timer_end(&t);
}

// Benchmark 3: Allocate-fill-free pattern
double bench_alloc_fill_free(bool use_custom)
{
	Timer t;

	timer_start(&t);
	for (int i = 0; i < ITERATIONS / 10; i++)
	{
		void *p = use_custom ? _malloc(MEDIUM_SIZE) : malloc(MEDIUM_SIZE);
		memset(p, 'A', MEDIUM_SIZE);
		use_custom ? _free(p) : free(p);
	}
	return timer_end(&t);
}

// Benchmark 4: Large allocations
double bench_large_allocs(bool use_custom)
{
	Timer t;
	void *ptrs[100];

	timer_start(&t);
	for (int i = 0; i < 100; i++)
	{
		ptrs[i] = use_custom ? _malloc(LARGE_SIZE) : malloc(LARGE_SIZE);
		memset(ptrs[i], 0, LARGE_SIZE);
	}
	for (int i = 0; i < 100; i++)
	{
		use_custom ? _free(ptrs[i]) : free(ptrs[i]);
	}
	return timer_end(&t);
}

// Benchmark 5: Fragmentation test
double bench_fragmentation(bool use_custom)
{
	Timer t;
	void *ptrs[1000];

	timer_start(&t);

	// Allocate many blocks
	for (int i = 0; i < 1000; i++)
	{
		ptrs[i] = use_custom ? _malloc(128) : malloc(128);
	}

	// Free every other one
	for (int i = 0; i < 1000; i += 2)
	{
		use_custom ? _free(ptrs[i]) : free(ptrs[i]);
	}

	// Allocate in freed spots
	for (int i = 0; i < 1000; i += 2)
	{
		ptrs[i] = use_custom ? _malloc(64) : malloc(64);
	}

	// Cleanup
	for (int i = 0; i < 1000; i++)
	{
		use_custom ? _free(ptrs[i]) : free(ptrs[i]);
	}

	return timer_end(&t);
}

// Benchmark 6: Realloc operations
double bench_realloc_ops(bool use_custom)
{
	Timer t;

	timer_start(&t);
	for (int i = 0; i < ITERATIONS / 100; i++)
	{
		void *p = use_custom ? _malloc(64) : malloc(64);
		p = use_custom ? _realloc(p, 256) : realloc(p, 256);
		p = use_custom ? _realloc(p, 1024) : realloc(p, 1024);
		p = use_custom ? _realloc(p, 128) : realloc(p, 128);
		use_custom ? _free(p) : free(p);
	}
	return timer_end(&t);
}

// Benchmark 7: Mixed workload
double bench_mixed_workload(bool use_custom)
{
	Timer t;
	void *ptrs[500] = {0};
	srand(42);

	timer_start(&t);
	for (int i = 0; i < ITERATIONS; i++)
	{
		int op = rand() % 4;
		int idx = rand() % 500;

		switch (op)
		{
		case 0: // malloc
			if (!ptrs[idx])
			{
				size_t size = 16 << (rand() % 8); // 16 to 2048
				ptrs[idx] = use_custom ? _malloc(size) : malloc(size);
			}
			break;
		case 1: // free
			if (ptrs[idx])
			{
				use_custom ? _free(ptrs[idx]) : free(ptrs[idx]);
				ptrs[idx] = NULL;
			}
			break;
		case 2: // realloc
			if (ptrs[idx])
			{
				size_t size = 16 << (rand() % 8);
				ptrs[idx] = use_custom ? _realloc(ptrs[idx], size)
				                       : realloc(ptrs[idx], size);
			}
			break;
		case 3: // calloc
			if (!ptrs[idx])
			{
				size_t size = (rand() % 256) + 1;
				ptrs[idx] = use_custom ? _calloc(size, 4) : calloc(size, 4);
			}
			break;
		}
	}

	// Cleanup
	for (int i = 0; i < 500; i++)
	{
		if (ptrs[i])
		{
			use_custom ? _free(ptrs[i]) : free(ptrs[i]);
		}
	}
	return timer_end(&t);
}

typedef struct
{
	const char *name;
	double (*benchmark)(bool);
} Benchmark;

typedef struct
{
	double min;
	double max;
	double mean;
	double median;
	double stddev;
} Stats;

// Calculate statistics from array of values
Stats calculate_stats(double *values, int n)
{
	Stats s = {0};

	// Min, max, sum
	s.min = values[0];
	s.max = values[0];
	double sum = 0;
	for (int i = 0; i < n; i++)
	{
		if (values[i] < s.min)
			s.min = values[i];
		if (values[i] > s.max)
			s.max = values[i];
		sum += values[i];
	}
	s.mean = sum / n;

	// Standard deviation
	double var_sum = 0;
	for (int i = 0; i < n; i++)
	{
		double diff = values[i] - s.mean;
		var_sum += diff * diff;
	}
	s.stddev = sqrt(var_sum / n);

	// Median (sort first)
	double sorted[n];
	memcpy(sorted, values, n * sizeof(double));
	for (int i = 0; i < n - 1; i++)
	{
		for (int j = i + 1; j < n; j++)
		{
			if (sorted[i] > sorted[j])
			{
				double tmp = sorted[i];
				sorted[i] = sorted[j];
				sorted[j] = tmp;
			}
		}
	}
	if (n % 2 == 0)
	{
		s.median = (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0;
	}
	else
	{
		s.median = sorted[n / 2];
	}

	return s;
}

void print_header(void)
{
	printf("\n");
	printf("╔══════════════════════════════════════════════════════════════════"
	       "═╗\n");
	printf("║          MEMORY ALLOCATOR BENCHMARK SUITE                        "
	       " ║\n");
	printf("╚══════════════════════════════════════════════════════════════════"
	       "═╝\n");
	printf("\n");
}

void print_separator(void)
{
	printf("───────────────────────────────────────────────────────────────────"
	       "─\n");
}

void run_benchmarks(void)
{
	Benchmark benchmarks[] = {
	    {"Sequential Small Allocs (10k × 64B)", bench_sequential_small},
	    /* {"Random Ops (100k ops)", bench_random_ops}, */
	    /* {"Alloc-Fill-Free (10k × 1KB)", bench_alloc_fill_free}, */
	    /* {"Large Allocations (100 × 8KB)", bench_large_allocs}, */
	    /* {"Fragmentation Test", bench_fragmentation}, */
	    /* {"Realloc Operations (1k ops)", bench_realloc_ops}, */
	    /* {"Mixed Workload (100k ops)", bench_mixed_workload}, */
	};

	int num_benchmarks = sizeof(benchmarks) / sizeof(benchmarks[0]);

	print_header();
	printf("Running each benchmark %d times and reporting median ± stddev\n\n",
	       NUM_RUNS);
	printf("%-40s %15s %15s %10s\n", "Benchmark", "Custom (ms)", "System (ms)",
	       "Ratio");
	print_separator();

	double total_custom_median = 0, total_system_median = 0;

	for (int i = 0; i < num_benchmarks; i++)
	{
		printf("Running: %-40s [", benchmarks[i].name);
		fflush(stdout);

		double custom_times[NUM_RUNS];
		double system_times[NUM_RUNS];

		// Run multiple times
		for (int run = 0; run < NUM_RUNS; run++)
		{
			custom_times[run] = benchmarks[i].benchmark(true);
			system_times[run] = benchmarks[i].benchmark(false);
			printf(".");
			fflush(stdout);
		}

		Stats custom_stats = calculate_stats(custom_times, NUM_RUNS);
		Stats system_stats = calculate_stats(system_times, NUM_RUNS);

		double ratio = custom_stats.median / system_stats.median;
		total_custom_median += custom_stats.median;
		total_system_median += system_stats.median;

		printf("]\r%-40s %9.2f ±%5.2f %9.2f ±%5.2f %9.2fx", benchmarks[i].name,
		       custom_stats.median, custom_stats.stddev, system_stats.median,
		       system_stats.stddev, ratio);

		// Color code the ratio
		if (ratio < 1.5)
		{
			printf(" ✓\n");
		}
		else if (ratio < 3.0)
		{
			printf(" ~\n");
		}
		else
		{
			printf(" ✗\n");
		}
	}

	print_separator();
	printf("%-40s %15.2f %15.2f %9.2fx\n", "TOTAL (median)",
	       total_custom_median, total_system_median,
	       total_custom_median / total_system_median);
	printf("\n");

	printf("Performance Analysis:\n");
	double ratio = total_custom_median / total_system_median;
	if (ratio < 1.2)
	{
		printf("  🎉 Excellent! Your allocator is competitive with system "
		       "malloc!\n");
	}
	else if (ratio < 2.0)
	{
		printf("  👍 Good! Your allocator is reasonably fast.\n");
	}
	else if (ratio < 5.0)
	{
		printf("  ⚠️  Fair. There's room for optimization.\n");
	}
	else
	{
		printf("  ⚠️  Your allocator is significantly slower than system "
		       "malloc.\n");
		printf("     Consider optimizing hot paths and reducing metadata "
		       "overhead.\n");
	}
	printf("\n");

	printf("Legend: ✓ = Good (<1.5x)  ~ = Fair (<3x)  ✗ = Slow (>3x)\n");
	printf("\n");
}

int main(void)
{
	run_benchmarks();
	return 0;
}
