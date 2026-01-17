## MEMORY ALLOCATOR - REMAINING TASKS

### **Phase 1: Core Fixes (Critical)**
- [x] Add alignment macro definitions (`ALIGN`, `ALIGN_UP`)
- [x] Implement alignment in `_malloc` (round up allocation sizes)
- [x] Test alignment with unaligned requests (e.g., 5 bytes)
- [x] Verify all returned pointers are 8-byte aligned

### **Phase 2: Standard Library Functions**
- [x] Implement `_calloc(size_t nmemb, size_t size)`
  - [x] Add overflow check
  - [x] Allocate memory using `_malloc`
  - [x] Zero-initialize with `memset`
  - [x] Test with array allocation

- [x] Implement `_realloc(void *ptr, size_t new_size)`
  - [x] Handle NULL pointer (redirect to malloc)
  - [x] Handle zero size (free and return NULL)
  - [x] Validate pointer with magic number
  - [x] Check if current block is large enough
  - [x] If not, allocate new block, copy data, free old
  - [x] Test growing and shrinking allocations

### **Phase 3: Multi-Page Support**
- [] Implement `expand_heap()` function
  - [x] Request new page via `mmap`
  - [x] Initialize new block header
  - [x] Find last block in current heap
  - [x] Link new page to existing heap
  - [x] Update prev/next pointers
- [x] Modify `_malloc` to call `expand_heap()` when out of memory
- [x] Test allocating more than 4KB total
- [x] Verify multiple pages are linked correctly

### **Phase 4: Testing & Validation**
- [x] Create comprehensive test suite
  - [x] Test alignment edge cases
  - [x] Test calloc zeros memory correctly
  - [x] Test realloc preserves data
  - [x] Test multi-page allocation
  - [x] Test allocating hundreds of small blocks
  - [x] Test fragmenting and coalescing repeatedly
- [x] Add heap consistency checker (walk list, verify all pointers)
- [x] Test buffer overflow detection (if you add red zones)


- [x] have another free_list with only freeblocks


- [ ] Add actual benchmarks - Compare malloc/free speed against glibc for 10M ops
- [ ] Measure fragmentation - Track (total_allocated / total_pages) over time
- [ ] Fix realloc - Actually implement shrinking properly
- [ ] Add thread safety - Even a single mutex would be better than nothing
- [ ] Implement size classes - Buckets for 16/32/64/128/256 bytes minimum
- [ ] Return pages to OS - munmap when large blocks are freed
- [ ] Write real tests - Memory leak detection, double-free catching, boundary testing



### **Phase 5: Documentation & Cleanup**
- [ ] Remove all TODO comments
- [ ] Add function documentation comments
- [ ] Clean up debug print statements
- [ ] Write README explaining your allocator
- [ ] Document known limitations

### **Optional: Advanced Features (If you want to go further)**
- [ ] Add heap statistics tracking
  - [ ] Total bytes allocated
  - [ ] Peak memory usage
  - [ ] Number of allocations
  - [ ] Fragmentation metrics
- [ ] Implement segregated free lists for common sizes
- [ ] Add thread safety with mutexes
- [ ] Implement large allocation optimization (direct mmap for >128KB)
- [ ] Add red zones for buffer overflow detection
- [ ] Create visualization tool to show heap state

