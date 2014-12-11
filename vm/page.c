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
#include "threads/thread.h"
#include "vm/swap.h"

static int page_lock_depth;
static struct lock page_lock;
static struct hash_elem* find_supp_page_entry(struct hash *supp_page_table, uint8_t *uaddr);

#define PAGE_POOL_SIZE 4000
static int pool_ptr = 0;
static struct supp_page_entry pool[PAGE_POOL_SIZE];

static void
acquire_page_lock(void)
{
	if (lock_held_by_current_thread(&page_lock))
		++page_lock_depth;
	else
		lock_acquire(&page_lock);
}

static void
release_page_lock(void)
{
	if (page_lock_depth > 0)
		--page_lock_depth;
	else
		lock_release(&page_lock);
}

struct supp_page_entry*
supp_page_find(struct hash *supp_page_table, uint8_t *uaddr)
{
	acquire_page_lock();
	struct hash_elem *e = NULL;
	struct supp_page_entry *item = (e = find_supp_page_entry(supp_page_table, uaddr)) ?
								   hash_entry(e, struct supp_page_entry, all_elem) : NULL;
	release_page_lock();
	return item;
}

void
supp_page_insert(struct hash *supp_page_table, uint8_t *upage, struct file *swap_file,
				 size_t swap_offset, size_t length, bool is_segment, bool is_writable)
{
	acquire_page_lock();
	struct supp_page_entry *item = &pool[pool_ptr++];
	ASSERT(pool_ptr <= PAGE_POOL_SIZE);

	item -> user_vaddr = upage;
	item -> swap_file = swap_file;
	item -> swap_offset = swap_offset;
	item -> length = length;
	item -> is_segment = is_segment;
	item -> is_writable = is_writable;

	hash_insert(supp_page_table, &item -> all_elem);

	release_page_lock();
}

void
supp_page_remove(struct hash *supp_page_table, uint8_t *upage)
{
	acquire_page_lock();
	struct hash_elem *e = find_supp_page_entry(supp_page_table, upage);
	
	if (e) {
		struct supp_page_entry *item = hash_entry(e, struct supp_page_entry, all_elem);
		hash_delete(supp_page_table, e);
		if (item -> swap_file == NULL)
			swap_free(item -> swap_offset);
	}

	release_page_lock();
}

static hash_action_func free_supp_page;

void
supp_page_destroy(struct hash *supp_page_table)
{
	acquire_page_lock();
	hash_destroy(supp_page_table, free_supp_page);
	release_page_lock();
}

static hash_hash_func hash_supp_page;
static hash_less_func less_supp_page;

static void free_supp_page
(struct hash_elem *elem, void *aux)
{
	acquire_page_lock();
	struct supp_page_entry *item = hash_entry(elem, struct supp_page_entry, all_elem);
	if (item -> swap_file == NULL)
		swap_free(item -> swap_offset);
	release_page_lock();
}

static unsigned hash_supp_page
(const struct hash_elem *elem, void *aux)
{
	return hash_int((int)(hash_entry(elem, struct supp_page_entry, all_elem)->user_vaddr));
}

static bool less_supp_page
(const struct hash_elem *lhs, const struct hash_elem *rhs, void *aux)
{
	return (unsigned)(hash_entry(lhs, struct supp_page_entry, all_elem) -> user_vaddr)
		 < (unsigned)(hash_entry(rhs, struct supp_page_entry, all_elem) -> user_vaddr);
}

static struct hash_elem*
find_supp_page_entry(struct hash *supp_page_table, uint8_t *uaddr)
{
	uint8_t *upage = (uint8_t*)((unsigned)(uaddr) / PGSIZE * PGSIZE);
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

#undef PAGE_POOL_SIZE
