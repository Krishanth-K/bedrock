## Day 1 - 2026-01-9

### Progress
- Started writing the malloc function.
- Used mmap to create some space in virtual memory.

### Task
Tomorrow i have to understand how to "mark" a portion of the virtual memory as "occupied", so other memory blocks
dont share it

### Notes

#### Problem
- Using mmap for a single malloc call is inefficient.
- Cause the os returns a page (4 kb), for any size of data.

#### Solution
- Request a single page from OS, and manage it manually.

---

## Day 2 - 2026-01-10

### Progress
- Added the block header and page header structs

---

## Day 3 - 2026-01-11

Im ditching the page header. Its too complex for now. 
Ill just stick to only block header and a single page for now

Implemented malloc properly.
Malloc can now choose a block if it has space, and then split the space for a new block (if there is enough minimum space for it).

### Issues
1. All blocks are tracked in teh free list now, need to optimizse that


---

## Day 4 - 2026-01-12

Starting "free" now. 
I need to add a "magic number" to each header, so that i can find if a pointer was malloc'ed 
or created in the stack. I should only free pointers that were malloc'ed

BOOM. Added colescing (whatever its called). 

### Decision
Switching to a doubly linked list, for better coalesing
Can switch to a footer for free blocks later

