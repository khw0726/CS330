#include "vm/swap.h"
#include <hash.h>
#include <bitmap.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "filesys/file.h"
#include "devices/block.h"
#include "threads/thread.h"
#include "lib/debug.h"

static struct lock block_lock;
static struct bitmap *used_slots;
static struct block *swap_block;

/* Set specific slot to unused slot. */
void
swap_free(const unsigned offset)
{
	lock_acquire(&block_lock);

	bitmap_set(used_slots, offset, false);

	lock_release(&block_lock);
}

/* Write contents of uaddr to swap space,
   then returns offset. */
unsigned
swap_write(const uint8_t *uaddr)
{
	lock_acquire(&block_lock);
	unsigned offset = 0, i = 0;
	offset = bitmap_scan_and_flip(used_slots, 0, 1, false);

	if (offset == BITMAP_ERROR) {
		lock_release(&block_lock);
		return BITMAP_ERROR;
	}

	/* One page equals to eight sectors. */
	for (i = 0; i < 8; i++) {
		block_write(swap_block, offset * 8 + i, uaddr + 512 * i);
	}

	lock_release(&block_lock);
	return offset;
}

void
swap_read(uint8_t *uaddr, const unsigned offset)
{
	lock_acquire(&block_lock);
	unsigned i = 0;

	/* One page equals to eight sectors. */
	for (i = 0; i < 8; i++) {
		block_read(swap_block, offset * 8 + i, uaddr + 512 * i);
	}

	lock_release(&block_lock);
}

void
swap_init(void)
{
	/* There're total 1024 swap slots(4M/4k). */
	used_slots = bitmap_create(1024);
	ASSERT((swap_block = block_get_role(BLOCK_SWAP)) != NULL);
	lock_init(&block_lock);
}
