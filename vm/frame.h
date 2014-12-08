#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <stdbool.h>
#include <stdint.h>
#include <hash.h>

/* How to allocate frames. */
enum frame_flags
  {
    FRM_ASSERT = 001,           /* Panic on failure. */
    FRM_ZERO = 002,             /* Zero page contents. */
    FRM_WRITABLE = 004              /* Writable page. */
  };

struct frame_entry {
	uint32_t* pagedir;

	uint8_t* user_vaddr;
	uint8_t* kernel_vaddr;

	/* Frame is writable if true. */
	bool writable;

	/* Do not evict when the frame is pinned. */
	bool pinned;

	struct thread *holder;
	struct hash_elem all_elem;
	struct list_elem vict_elem;
};

uint8_t* frame_get_page(struct hash *frame_table, uint8_t* upage, enum frame_flags flags);
void frame_free_page(struct hash *frame_table, uint8_t* upage);
void frame_free_all(struct hash *frame_table);
void frame_init(void);
void frame_init_table(struct hash *frame_table);
struct hash_elem* frame_find_upage(struct hash *frame_table, uint8_t* upage);

#endif /* vm/frame.h */
