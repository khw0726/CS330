#include "vm/frame.h"
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

static struct lock frame_lock;

uint8_t*
frame_get_page(struct hash *frame_table, uint8_t* upage, enum frame_flags flags)
{
	lock_acquire(&frame_lock);
	enum palloc_flags pal_flags = PAL_USER;

	if (flags & FRM_ZERO) {
		pal_flags |= PAL_ZERO;
	}

	if (flags & FRM_ASSERT) {
		pal_flags |= PAL_ASSERT;
	}

	uint8_t* frame = (uint8_t*)palloc_get_page(pal_flags);

	struct frame_entry *item = NULL;
	if (frame == NULL) {
		// Failed to allocate new frame.
		// TODO: Evict other frame(s) to allocate new frame.
		lock_release(&frame_lock);
		return NULL;
	}

	item = (struct frame_entry*)malloc(sizeof *item);
	item -> pagedir = thread_current() -> pagedir;
	item -> user_vaddr = upage;
	item -> kernel_vaddr = frame;
	item -> writable = true && (flags & FRM_WRITABLE);
	hash_insert(frame_table, &item->all_elem);
	pagedir_set_page(item->pagedir, item->user_vaddr, item->kernel_vaddr, item->writable);

	lock_release(&frame_lock);
	return frame;
}

void
frame_free_page(struct hash *frame_table, uint8_t* upage)
{
	lock_acquire(&frame_lock);
	struct hash_elem *ptr = frame_find_upage(frame_table, upage);
	if (ptr != NULL) {
		struct frame_entry *item = hash_entry(ptr, struct frame_entry, all_elem);
		hash_delete(frame_table, &item->all_elem);
		pagedir_clear_page(item->pagedir, item->user_vaddr);
		free(item);
	}
	lock_release(&frame_lock);
}

static hash_action_func free_frame;

void
frame_free_all(struct hash *frame_table)
{
	hash_destroy(frame_table, free_frame);
}

struct hash_elem*
frame_find_upage(struct hash *frame_table, uint8_t* upage)
{
	struct frame_entry dummy;
	dummy.user_vaddr = upage;
	return hash_find(frame_table, &dummy.all_elem);
}

static hash_hash_func hash_frame;
static hash_less_func less_frame;

static void free_frame
(struct hash_elem *elem, void *aux)
{
	frame_free_page((struct hash*)aux, hash_entry(elem, struct frame_entry, all_elem) -> user_vaddr);
}

static unsigned hash_frame
(const struct hash_elem *elem, void *aux)
{
	return hash_int((int)hash_entry(elem, struct frame_entry, all_elem)->user_vaddr);
}

static bool less_frame
(const struct hash_elem *lhs, const struct hash_elem *rhs, void *aux)
{
	return hash_entry(lhs, struct frame_entry, all_elem) -> user_vaddr
		 < hash_entry(rhs, struct frame_entry, all_elem) -> user_vaddr;
}

/* Initialize frame table. */
void
frame_init(void)
{
	lock_init(&frame_lock);
}

void
frame_init_table(struct hash *frame_table)
{
	hash_init(frame_table, hash_frame, less_frame, frame_table);
}
