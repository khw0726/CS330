#include "vm/page.h"
#include <bitmap.h>
#include <hash.h>
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "userprog/pagedir.h"
#include "threads/pte.h"
#include "threads/palloc.h"
#include "threads/loader.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "threads/thread.h"

struct supp_page_entry*
supp_page_find(uint8_t *uaddr)
{
	/* Step 1: Find upage from uaddr. */
	uint8_t *upage = (uint8_t*)((int)(uaddr) / PGSIZE * PGSIZE);
	struct supp_page_entry dummy;
	dummy.user_vaddr = upage;
	struct hash_elem *e = hash_find(&thread_current() -> supp_page_table, &dummy.all_elem);

	if (e) {
		return hash_entry(e, struct supp_page_entry, all_elem);
	}

	return NULL;
}

void
supp_page_insert(uint8_t *upage, struct file *swap_file, size_t swap_offset, size_t length)
{
	struct supp_page_entry *item = malloc(sizeof *item);
}

void
supp_page_remove(uint8_t *upage)
{
}

void
supp_page_destroy(void)
{
}

static hash_hash_func hash_supp_page;
static hash_less_func less_supp_page;

static unsigned hash_supp_page
(const struct hash_elem *elem, void *aux)
{
	return hash_int((int)hash_entry(elem, struct supp_page_entry, all_elem)->user_vaddr);
}

static bool less_supp_page
(const struct hash_elem *lhs, const struct hash_elem *rhs, void *aux)
{
	return hash_entry(lhs, struct supp_page_entry, all_elem) -> user_vaddr
		 < hash_entry(rhs, struct supp_page_entry, all_elem) -> user_vaddr;
}

void
supp_page_init(void)
{
	hash_init(&thread_current() -> supp_page_table, hash_supp_page, less_supp_page, NULL);
}
