#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <hash.h>
#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "threads/synch.h"

/* States in a thread's life cycle. */
enum thread_status
  {
    THREAD_RUNNING,     /* Running thread. */
    THREAD_READY,       /* Not running but ready to run. */
    THREAD_BLOCKED,     /* Waiting for an event to trigger. */
    THREAD_DYING        /* About to be destroyed. */
  };

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */

/* A kernel thread or user process.

   Each thread structure is stored in its own 4 kB page.  The
   thread structure itself sits at the very bottom of the page
   (at offset 0).  The rest of the page is reserved for the
   thread's kernel stack, which grows downward from the top of
   the page (at offset 4 kB).  Here's an illustration:

        4 kB +---------------------------------+
             |          kernel stack           |
             |                |                |
             |                |                |
             |                V                |
             |         grows downward          |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             +---------------------------------+
             |              magic              |
             |                :                |
             |                :                |
             |               name              |
             |              status             |
        0 kB +---------------------------------+

   The upshot of this is twofold:

      1. First, `struct thread' must not be allowed to grow too
         big.  If it does, then there will not be enough room for
         the kernel stack.  Our base `struct thread' is only a
         few bytes in size.  It probably should stay well under 1
         kB.

      2. Second, kernel stacks must not be allowed to grow too
         large.  If a stack overflows, it will corrupt the thread
         state.  Thus, kernel functions should not allocate large
         structures or arrays as non-static local variables.  Use
         dynamic allocation with malloc() or palloc_get_page()
         instead.

   The first symptom of either of these problems will probably be
   an assertion failure in thread_current(), which checks that
   the `magic' member of the running thread's `struct thread' is
   set to THREAD_MAGIC.  Stack overflow will normally change this
   value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
   the run queue (thread.c), or it can be an element in a
   semaphore wait list (synch.c).  It can be used these two ways
   only because they are mutually exclusive: only a thread in the
   ready state is on the run queue, whereas only a thread in the
   blocked state is on a semaphore wait list. */

/* Since wait() can be called even though the child is dead,
   It is necessary to conserve child's dying message.
   To manage children(plural!), list will be used. */
#ifdef USERPROG
struct child
{
	tid_t tid;
	int exit_code;
	struct list_elem elem;
};

struct fdesc {
	int fd;
	struct file *file;
	struct list_elem elem;
};

struct mdesc {
	int md;
	uint8_t *upage;
	unsigned length;
	struct file *file;
	struct list_elem elem;
};
#endif

/* For priority donation,
   save donation records. */
struct donation
{
	void *lock; /* Identified by address of the lock(or semaphore). */
	tid_t tid;
	int priority; /* Donated priority. */
	struct list_elem elem; /* Caution: the list will be ordered list. */
};

struct thread
  {
    /* Owned by thread.c. */
    tid_t tid;                          /* Thread identifier. */
    enum thread_status status;          /* Thread state. */
    char name[16];                      /* Name (for debugging purposes). */
    uint8_t *stack;                     /* Saved stack pointer. */
    int priority;                       /* Priority. */
    struct list_elem allelem;           /* List element for all threads list. */

    /* Shared between thread.c and synch.c. */
    struct list_elem elem;              /* List element. */

	/* For priority donation. */
	int own_priority; /* my original priority. */
	struct list donated; /* *Ordered* list of donated priorities. */
	struct lock *blocked_for; /* the lock I am currently waiting for */

	/* For priority aging. */
	int age;

	/* For mlfqs */
	int64_t nice;
	int64_t recent_cpu;

#ifdef USERPROG
    /* Owned by userprog/process.c. */
    uint32_t *pagedir;                  /* Page directory. */
	int exit_code;

	/* for synchronization. */
	bool is_alive;
	tid_t waiting_for;
	/* thread(process) tree. */
	struct thread *parent;
	struct list children;
	struct semaphore exec_lock;
	/* file, and file descriptors. */
	struct list files;
	int last_fd;
	/* for Read-Only-Executable. */
	struct file *myself;
#endif

#ifdef VM
	uint8_t *esp;
	int last_md;
	struct list maps;
	struct hash frame_table;
	struct hash supp_page_table;
	struct lock thread_page_lock;
#endif

    /* Owned by thread.c. */
    unsigned magic;                     /* Detects stack overflow. */
  };

/* For priority scheduling */
bool thread_priority_less(const struct list_elem *a, const struct list_elem *b, void *aux);
bool donation_less(const struct list_elem *a, const struct list_elem *b, void *aux);

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;
/* for mlfqs.. */
void thread_mlfqs_update(bool update_priority_only);

void thread_init (void);
void thread_start (void);

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_unblock (struct thread *);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);

/* Retrieve thread by tid. */
struct thread *thread_from_tid (tid_t tid);

/* Performs some operation on thread t, given auxiliary data AUX. */
typedef void thread_action_func (struct thread *t, void *aux);
void thread_foreach (thread_action_func *, void *);

int thread_get_priority (void);
void thread_set_priority (int);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);

#endif /* threads/thread.h */
