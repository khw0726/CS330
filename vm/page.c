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
#include "vm/swap.h"

static struct lock page_lock;
static struct hash_elem* find_supp_page_entry(struct hash *supp_page_table, uint8_t *uaddr);

struct supp_page_entry*
supp_page_find(struct hash *supp_page_table, uint8_t *uaddr)
{
	lock_acquire(&page_lock);
	struct hash_elem *e = NULL;
	struct supp_page_entry *item = (e = find_supp_page_entry(supp_page_table, uaddr)) ?
								   hash_entry(e, struct supp_page_entry, all_elem) : NULL;
	lock_release(&page_lock);
	return item;
}

void
supp_page_insert(struct hash *supp_page_table, uint8_t *upage, struct file *swap_file,
				 size_t swap_offset, size_t length, bool is_segment, bool is_writable)
{
	lock_acquire(&page_lock);
	struct supp_page_entry *item = malloc(sizeof *item);

	item -> user_vaddr = upage;
	item -> swap_file = swap_file;
	item -> swap_offset = swap_offset;
	item -> length = length;
	item -> is_segment = is_segment;
	item -> is_writable = is_writable;

	hash_insert(supp_page_table, &item -> all_elem);

	lock_release(&page_lock);
}

void
supp_page_remove(struct hash *supp_page_table, uint8_t *upage)
{
	lock_acquire(&page_lock);
	struct hash_elem *e = find_supp_page_entry(supp_page_table, upage);
	
	if (e) {
		struct supp_page_entry *item = hash_entry(e, struct supp_page_entry, all_elem);
		hash_delete(supp_page_table, e);
		if (item -> swap_file == NULL)
			swap_free(item -> swap_offset);
		free(item);
	}

	lock_release(&page_lock);
}

static hash_action_func free_supp_page;

void
supp_page_destroy(struct hash *supp_page_table)
{
	hash_destroy(supp_page_table, free_supp_page);
}

static hash_hash_func hash_supp_page;
static hash_less_func less_supp_page;

static void free_supp_page
(struct hash_elem *elem, void *aux)
{
	supp_page_remove((struct hash*)aux, hash_entry(elem, struct supp_page_entry, all_elem) -> user_vaddr);
}

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

static struct hash_elem*
find_supp_page_entry(struct hash *supp_page_table, uint8_t *uaddr)
{
	uint8_t *upage = (uint8_t*)((int)(uaddr) / PGSIZE * PGSIZE);
	struct supp_page_entry dummy;
	dummy.user_vaddr = upage;
	struct hash_elem *e = hash_find(supp_page_table, &dummy.all_elem);

	return e;
}


void
supp_page_init(void)
{
	lock_init(&page_lock);
}

void
supp_page_init_table(struct hash *supp_page_table)
{
	hash_init(supp_page_table, hash_supp_page, less_supp_page, supp_page_table);
}
