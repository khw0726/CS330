#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "threads/thread.h"
#include "filesys/file.h"

struct supp_page_entry {
	uint8_t* user_vaddr;
	/* NULL if typical swap file, otherwise code/data segment.
	   Anyway, the file never be closed because this is only an alias. */
	struct file* swap_file;
	size_t swap_offset;
	size_t length;
	
	struct hash_elem all_elem;
};

struct supp_page_entry* supp_page_find(uint8_t* uaddr);
void supp_page_init(void);
void supp_page_insert(uint8_t *upage, struct file *swap_file, size_t swap_offset, size_t length);

#endif /* vm/page.h */
