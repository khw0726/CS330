#include "vm/frame.h"
#include <bitmap.h>
#include <list.h>
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
#include "vm/page.h"
#include "vm/swap.h"

static int frame_lock_depth;
static struct lock frame_lock;
static struct list frame_list;
static struct list_elem *clock_hand;
static uint8_t* find_victim(void);

static void
acquire_frame_lock(void)
{
	if (lock_held_by_current_thread(&frame_lock))
		++frame_lock_depth;
	else
		lock_acquire(&frame_lock);
}

static void
release_frame_lock(void)
{
	if (frame_lock_depth > 0)
		--frame_lock_depth;
	else
		lock_release(&frame_lock);
}

/* CLOCK page replacement algorithm implementation.
   It returns kernel page of evicted frame. */
static uint8_t*
find_victim(void)
{
	acquire_frame_lock();

	int loop_cnt = list_size(&frame_list) << 1;

	/* Circulate whole list to find victim. */
	while (loop_cnt --> 0) {
		if (clock_hand == NULL || clock_hand == list_end(&frame_list)) {
			clock_hand = list_begin(&frame_list);
		}

		/* Find pte for this frame, then investigate accessed bit(&PTE_A). */
		struct frame_entry *e = list_entry(clock_hand, struct frame_entry, vict_elem);

		if (e -> pinned) { /* pinned frame, do NOT evict at this time. */
			if (clock_hand != list_end(&frame_list))
				clock_hand = list_next(clock_hand);
			else
				clock_hand = NULL;
			continue;
		}

		lock_acquire(&e->holder->thread_page_lock);
		if (pagedir_is_accessed(e -> pagedir, e -> user_vaddr)) {
			/* Give second chance. */
			pagedir_set_accessed(e -> pagedir, e -> user_vaddr, false);
			lock_release(&e->holder->thread_page_lock);
			if (clock_hand != list_end(&frame_list))
				clock_hand = list_next(clock_hand);
			else
				clock_hand = NULL;
		} else {
			lock_release(&e->holder->thread_page_lock);
			/* Evict this. */
			unsigned offset = BITMAP_ERROR;
			if (clock_hand != list_end(&frame_list))
				clock_hand = list_next(clock_hand);
			else
				clock_hand = NULL;
			if (e -> writable)
				offset = swap_write(e -> kernel_vaddr);
			if (offset != BITMAP_ERROR || !e -> writable) {
				lock_acquire(&e->holder->thread_page_lock);
				list_remove(&e -> vict_elem);
				hash_delete(&e -> holder -> frame_table, &e -> all_elem);
				pagedir_clear_page(e -> pagedir, e -> user_vaddr);
				lock_release(&e->holder->thread_page_lock);
				uint8_t *kpage = e -> kernel_vaddr;
				if (e -> writable) {
					if (supp_page_find(&e -> holder -> supp_page_table, e -> user_vaddr) != NULL)
						supp_page_remove(&e -> holder -> supp_page_table, e -> user_vaddr);
					supp_page_insert(&e -> holder -> supp_page_table, e -> user_vaddr,
									 NULL, offset, PGSIZE, false, true);
				}
				free(e);
				release_frame_lock();
				return kpage;
			} else {
				release_frame_lock();
				return NULL;
			}

		}

	}

	release_frame_lock();
	return NULL;
}

/* Allocate new frame(or evict other frames), and return. */
uint8_t*
frame_get_page(struct hash *frame_table, uint8_t* upage, enum frame_flags flags)
{
	acquire_frame_lock();

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
		/* Failed to allocate new frame.
		   Use swap to resolve this situation! */
		frame = find_victim();

		if (frame == NULL) {
			release_frame_lock();
			return NULL;
		}

		if (flags & FRM_ZERO)
			memset(frame, 0, PGSIZE);

	}

	item = (struct frame_entry*)malloc(sizeof *item);
	ASSERT (item != NULL);
	lock_acquire(&thread_current()->thread_page_lock);
	item -> pagedir = thread_current() -> pagedir;
	item -> user_vaddr = upage;
	item -> kernel_vaddr = frame;
	item -> holder = thread_current();
	item -> writable = true && (flags & FRM_WRITABLE);
	item -> pinned = false;
	hash_insert(frame_table, &item->all_elem);
	list_push_back(&frame_list, &item->vict_elem);
	pagedir_set_page(item->pagedir, item->user_vaddr, item->kernel_vaddr, item->writable);
	lock_release(&thread_current()->thread_page_lock);

	release_frame_lock();
	return frame;
}

void
frame_free_page(struct hash *frame_table, uint8_t* upage)
{
	acquire_frame_lock();

	struct hash_elem *ptr = frame_find_upage(frame_table, upage);
	if (ptr != NULL) {
		struct frame_entry *item = hash_entry(ptr, struct frame_entry, all_elem);
		if (&item->vict_elem == clock_hand) {
			if (clock_hand != list_end(&frame_list))
				clock_hand = list_next(clock_hand);
			else
				clock_hand = NULL;
		}
		lock_acquire(&thread_current()->thread_page_lock);
		list_remove(&item->vict_elem);
		hash_delete(frame_table, &item->all_elem);
		pagedir_clear_page(item->pagedir, item->user_vaddr);
		lock_release(&thread_current()->thread_page_lock);
		palloc_free_page(item->kernel_vaddr);
		free(item);
	}

	release_frame_lock();
}

static hash_action_func free_frame;

void
frame_free_all(struct hash *frame_table)
{
	acquire_frame_lock();
	hash_destroy(frame_table, free_frame);
	release_frame_lock();
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
	acquire_frame_lock();
	struct frame_entry *item = hash_entry(elem, struct frame_entry, all_elem);
	list_remove(&item -> vict_elem);
	pagedir_clear_page(item -> pagedir, item -> user_vaddr);
	palloc_free_page(item -> kernel_vaddr);
	free(item);
	release_frame_lock();
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
	clock_hand = NULL;
	frame_lock_depth = 0;
	lock_init(&frame_lock);
	list_init(&frame_list);
}

void
frame_init_table(struct hash *frame_table)
{
	hash_init(frame_table, hash_frame, less_frame, NULL);
}
