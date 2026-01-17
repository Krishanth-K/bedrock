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

Added calloc. it was very simple, cause i already have _malloc

### Problem
Ahhhhh spent 2+ trying to debug a segfult. no progress
the segfault happens when i try to test the expandPage. commenting out the *coalesce()* in the
realloc function seems to solve it. 

### Progress
- Implemented free
- Implemented calloc
- Added alignment


### Decision
Switching to a doubly linked list, for better coalesing
Can switch to a footer for free blocks later


---

## Day 5 - 2026-01-13

### Problem
Spent almost another hour debugging the segfault
Works in the online compiler, but not on mine ???

Found a fix
compiling with ` cc -g -O0 -fsanitize=address -fsanitize=undefined main.c`
makes it run without issues

Soo compiling with optimisation seems to create undefined behaviour (howww??)


FIXED IT!!!
The issues was my code assumed that new page would be adjacent to the first page.
But that was wrong

I tried to merge two blocks from non-adjacent pages, leading to UB. The fix was to check
if the pages are adjacent before trying to colaesce them


### Problem
New issue
when i try to allocate 5000 bytes (> a page size), new page is created, but its not adjacent
so cant coalesce with it, results in a space < 5000 bytes, so create another page and so on ....
leading to an infinite loop

FIX: create pages adjacent to the current page.



### Progress
- Fixed the segfault while adding a new page
- Abstracted the files
- Added cmake to build and run the files

---

## Day 6 - 2026-01-17

New ideas new ideas.
Instead of creating new pages and hoping they would be adjacent. im going to allocate huge spaces, and then
create and link them

