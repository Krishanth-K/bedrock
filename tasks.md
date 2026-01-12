## MEMORY ALLOCATOR - REMAINING TASKS

### **Phase 1: Core Fixes (Critical)**
- [ ] Add alignment macro definitions (`ALIGN`, `ALIGN_UP`)
- [ ] Implement alignment in `_malloc` (round up allocation sizes)
- [ ] Test alignment with unaligned requests (e.g., 5 bytes)
- [ ] Verify all returned pointers are 8-byte aligned

### **Phase 2: Standard Library Functions**
- [ ] Implement `_calloc(size_t nmemb, size_t size)`
  - [ ] Add overflow check
  - [ ] Allocate memory using `_malloc`
  - [ ] Zero-initialize with `memset`
  - [ ] Test with array allocation

- [ ] Implement `_realloc(void *ptr, size_t new_size)`
  - [ ] Handle NULL pointer (redirect to malloc)
  - [ ] Handle zero size (free and return NULL)
  - [ ] Validate pointer with magic number
  - [ ] Check if current block is large enough
  - [ ] If not, allocate new block, copy data, free old
  - [ ] Test growing and shrinking allocations

### **Phase 3: Multi-Page Support**
- [ ] Implement `expand_heap()` function
  - [ ] Request new page via `mmap`
  - [ ] Initialize new block header
  - [ ] Find last block in current heap
  - [ ] Link new page to existing heap
  - [ ] Update prev/next pointers
- [ ] Modify `_malloc` to call `expand_heap()` when out of memory
- [ ] Test allocating more than 4KB total
- [ ] Verify multiple pages are linked correctly

### **Phase 4: Testing & Validation**
- [ ] Create comprehensive test suite
  - [ ] Test alignment edge cases
  - [ ] Test calloc zeros memory correctly
  - [ ] Test realloc preserves data
  - [ ] Test multi-page allocation
  - [ ] Test allocating hundreds of small blocks
  - [ ] Test fragmenting and coalescing repeatedly
- [ ] Add heap consistency checker (walk list, verify all pointers)
- [ ] Test buffer overflow detection (if you add red zones)

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

---

**START WITH PHASE 1, TASK 1.** Add the alignment macros and show me the code.
