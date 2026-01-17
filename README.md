# Custom High-Performance Memory Allocator

A high-throughput, low-latency memory allocator implementation in C, designed to compete with standard system allocators in specific workloads. This project aims to bridge the gap between educational implementations and production-grade memory managers like `jemalloc` or `ptmalloc`.

## 🎯 Project Goals

- **High Concurrency:** Minimize lock contention via thread-local heaps (planned).
- **Cache Efficiency:** Optimize data locality and reduce cache misses.
- **Memory Efficiency:** Advanced coalescing and page reclamation strategies to minimize fragmentation.
- **Robustness:** Built-in integrity checks and hardened metadata handling.

## 🚀 Current Architecture

The allocator implements a **First-Fit strategy** using an **Explicit Free List** (LIFO) for O(1) free and O(K) allocation performance. It maintains two parallel structures:
 - **Physical List:** Doubly-linked list of all blocks (allocated & free) sorted by address for coalescing.
 - **Logical Free List:** Singly-linked list of only free blocks for fast allocation.

 It interacts directly with the kernel via `mmap` to manage virtual memory pages.

### Core Features
- **Standard API Compliance:** Full implementation of `malloc`, `free`, `calloc`, and `realloc`.
- **High Performance:**
  - **Explicit Free List:** Allocations iterate only free blocks, not allocated ones.
  - **O(1) Free:** Freed blocks are inserted at the head of the free list.
- **Dynamic Heap Management:**
  - Automatic page acquisition via `mmap`.
  - Block splitting for efficient space utilization.
  - Forward and backward coalescing to combat external fragmentation.
- **Memory Safety:**
  - Block header validation (Magic numbers).
  - Double-free detection guards.
  - 8-byte alignment enforcement.

## 🗺️ Roadmap & Advanced Features

This project is under active development. The following architectural enhancements are scheduled for upcoming releases:

### 1. Performance Optimization
- [x] **Explicit Free List:** Maintain a separate list of free blocks to avoid scanning allocated memory.
- [x] **Benchmark Suite:** Comprehensive performance comparison against `glibc`.
- [ ] **Size Classes (Segregated Fits):** Implementation of size buckets (e.g., 16, 32, 64, 128, 256 bytes) to achieve O(1) allocation time for small objects.
- [ ] **Thread Safety:** Integration of fine-grained mutex locking to support multi-threaded applications.

### 2. Memory Efficiency
- [ ] **Fragmentation Metrics:** Real-time tracking of `total_allocated` vs `total_pages` to monitor heap health.
- [ ] **Page Reclamation:** Implementation of `munmap` logic to release large unused memory chunks back to the OS.
- [ ] **Optimized Reallocation:** In-place shrinking for `realloc` to avoid unnecessary data copying.

### 3. Reliability & Testing
- [ ] **Advanced Test Harness:** Automated detection for memory leaks, buffer overflows, and boundary violations.
- [ ] **Fuzz Testing:** Stress testing the allocator with randomized allocation patterns to ensure stability under load.

## 📂 Project Structure

```
.
├── include/        # Public API and internal headers
├── src/            # Core implementation
│   ├── mem.c       # Allocator logic
│   ├── benchmark.c # Performance benchmarking suite
│   └── test.c      # Unit and integration tests
├── build/          # Build artifacts
└── BENCHMARK.md    # Performance analysis and optimization logs
```

## 🛠️ Build & Usage

### Prerequisites
- C11 compliant compiler (GCC/Clang)
- CMake 3.16+
- Linux environment (due to `mmap`/`unistd.h` dependencies)

### Compilation

```bash
# Build the library and test suite
make all

# Run the comprehensive benchmark
make bench
```

### Integration

Link against the static object or library in your build system:

```c
#include "mem.h"

void critical_section() {
    // High-performance allocation
    void *buffer = _malloc(1024);
    
    // ... processing ...
    
    _free(buffer);
}
```

## 📊 Benchmarks

Current benchmarking focuses on baseline overhead. See [BENCHMARK.md](BENCHMARK.md) for detailed latency breakdowns and comparison against system defaults.

## 📝 License

This project is open-source software.
