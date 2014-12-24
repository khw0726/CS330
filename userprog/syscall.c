#include "userprog/syscall.h"
#include <hash.h>
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
//added to use file_close!
#include "filesys/file.h"
#include "threads/malloc.h"
#include "vm/frame.h"
#include "vm/page.h"
typedef int pid_t;

static void syscall_handler (struct intr_frame *);
static bool is_valid_user_addr (const uint8_t *uaddr, bool write);
static int get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);

//Syscall Handlers.
static void exit_handler (int status);
static int write_handler (int fd, const void *buffer, unsigned size);
static int read_handler (int fd, void *buffer, unsigned size);
static void halt_handler (void);
static pid_t exec_handler (const char *cmd_line);
static int wait_handler (pid_t pid);
static int fibonacci (int n);
static int sum_of_four_integers (int a, int b, int c, int d);
static bool remove_handler (const char *file_name);
static bool create_handler (const char *file_name, unsigned initial_size);
static int open_handler (const char *file_name);
static void close_handler (int fd);
static int filesize_handler (int fd);
static void seek_handler (int fd, unsigned position);
static unsigned tell_handler (int fd);
static int mmap_handler (int fd, uint8_t *upage);
void munmap_handler (int md);

/* Mutex for file access. */
struct lock file_access_lock;

/* Mutex for mmap access. */
struct lock mmap_access_lock;

/* Returns true if uaddr is valid user memory.
   this function should be called before every dereference. */
#define STACK_LIMIT (uint8_t*)((uint8_t*)(PHYS_BASE) - (uint8_t*)(8*1024*1024))
static bool
is_valid_user_addr (const uint8_t *uaddr, bool write)
{
	if (uaddr >= PHYS_BASE) return false;

	if (write &&
		frame_find_upage(&thread_current()  -> frame_table, (uint8_t*)((unsigned)uaddr / PGSIZE * PGSIZE)) &&
		!hash_entry(frame_find_upage(&thread_current()  -> frame_table,
					(uint8_t*)((unsigned)uaddr / PGSIZE * PGSIZE)), struct frame_entry, all_elem) -> writable)
		return false;

	if (pagedir_get_page(thread_current()->pagedir, uaddr) != NULL)
		return true;

	struct supp_page_entry *e = NULL;
	if (e = supp_page_find(&thread_current() -> supp_page_table, uaddr)) {
		uint8_t *fault_page = (uint8_t*)((unsigned)uaddr / PGSIZE * PGSIZE);
		/* Lazy Loading of Segments */
		if (e -> is_segment) {
			uint8_t *frm = frame_get_page(&thread_current() -> frame_table, fault_page,
					(e -> is_writable ? FRM_WRITABLE : 0) | FRM_ZERO);
			if (frm) {
				file_seek(e -> swap_file, e -> swap_offset);
				if (file_read (e -> swap_file, frm, e -> length) == (int) e -> length)
					return true;
				frame_free_page(&thread_current() -> frame_table, fault_page);
				return false;
			}
			return false;
		} else if (e && e -> is_mmap) {
			uint8_t *frm = frame_get_page(&thread_current() -> frame_table, fault_page,
					(e -> is_writable ? FRM_WRITABLE : 0) | FRM_ZERO);
			if (frm) {
				file_seek(e -> swap_file, e -> swap_offset);
				if (file_read (e -> swap_file, frm, e -> length) == (int) e -> length)
					return true;
				frame_free_page(&thread_current() -> frame_table, fault_page);
				return false;
			}
			return false;
		} else if (e) {
			/* Swapped out pages. */
			uint8_t * frm = frame_get_page(&thread_current() -> frame_table, fault_page,
										   (e -> is_writable ? FRM_WRITABLE : 0) | FRM_ZERO);
			if (frm) {
				swap_read(frm, e -> swap_offset);
				supp_page_remove(&thread_current()->supp_page_table, fault_page);
				return true;
			}

			return false;
		}
	}

	if (write &&
		STACK_LIMIT <= thread_current() -> esp && thread_current() -> esp < PHYS_BASE &&
		STACK_LIMIT <= uaddr && uaddr < PHYS_BASE &&
		uaddr >= thread_current() -> esp) {
		/* Stack growth. */
		bool success = false;
		uint8_t *stack_ptr1= (uint8_t*)(((unsigned)(uaddr)) / PGSIZE * PGSIZE) + PGSIZE;
		uint8_t *stack_ptr2= (uint8_t*)(((unsigned)(thread_current()->esp)) / PGSIZE * PGSIZE) + PGSIZE;
		uint8_t *stack_ptr = stack_ptr1 > stack_ptr2 ? stack_ptr1 : stack_ptr2;

		while (stack_ptr > thread_current()->esp || stack_ptr > uaddr) {
			stack_ptr -= PGSIZE;
			if (frame_find_upage(&thread_current()  -> frame_table, stack_ptr))
				continue;
			if (frame_get_page(&thread_current()  -> frame_table, stack_ptr, FRM_WRITABLE | FRM_ZERO) == NULL)
				break;
		}

		if (stack_ptr <= thread_current()->esp && stack_ptr <= uaddr)
			success = true;

		return success; 
	}

	return false;
}

void
syscall_init (void) 
{
  lock_init(&mmap_access_lock);
  lock_init(&file_access_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

#define kth(esp,k) (esp+k*sizeof(char*))
#define get_arg(esp,k,type) *(type*)(kth(esp,k))
#define is_user_vaddr_after(esp,k,type) (is_user_vaddr(kth(esp,k+1)-1))
#define SYSTEMCALL_HANDLER_LIST 0
#define syscall_return (f->eax) 
static void
syscall_handler (struct intr_frame *f) 
{
	char *esp = f -> esp;
	int syscall_number = -1;
	thread_current() -> esp = f -> esp;

	if (is_valid_user_addr(esp, false) &&
		is_user_vaddr_after(esp, 0, int)) {
		syscall_number = *(int*)esp;
	}

	if (SYSTEMCALL_HANDLER_LIST) {
	} else if (syscall_number == SYS_EXIT &&
			is_user_vaddr_after(esp, 1, int) &&
			is_valid_user_addr(kth(esp, 1), false)) {
		exit_handler(get_arg(esp, 1, int));
	} else if (syscall_number == SYS_REMOVE &&
			is_valid_user_addr(kth(esp, 1), false) &&
			is_user_vaddr_after(esp, 1, char*)) {
		syscall_return = remove_handler(get_arg(esp, 1, char*));
	} else if (syscall_number == SYS_CREATE &&
			is_valid_user_addr(kth(esp, 1), false) &&
			is_user_vaddr_after(esp, 1, char*) &&
			is_valid_user_addr(kth(esp, 2), false) &&
			is_user_vaddr_after(esp, 2, unsigned)) {
		syscall_return = create_handler(get_arg(esp, 1, char*), get_arg(esp, 2, unsigned));
	} else if (syscall_number == SYS_OPEN &&
			is_valid_user_addr(kth(esp, 1), false) &&
			is_user_vaddr_after(esp, 1, char*)) {
		syscall_return = open_handler(get_arg(esp, 1, char*));
	} else if (syscall_number == SYS_CLOSE &&
			is_valid_user_addr(kth(esp, 1), false) &&
			is_user_vaddr_after(esp, 1, int)) {
		close_handler(get_arg(esp, 1, int));
	} else if (syscall_number == SYS_SEEK &&
			is_valid_user_addr(kth(esp, 1), false) &&
			is_user_vaddr_after(esp, 1, int) &&
			is_valid_user_addr(kth(esp, 2), false) &&
			is_user_vaddr_after(esp, 2, unsigned)) {
		seek_handler(get_arg(esp, 1, int), get_arg(esp, 2, unsigned));
	} else if (syscall_number == SYS_TELL &&
			is_valid_user_addr(kth(esp, 1), false) &&
			is_user_vaddr_after(esp, 1, int)) {
		syscall_return = tell_handler(get_arg(esp, 1, int));
	} else if (syscall_number == SYS_FILESIZE &&
			is_valid_user_addr(kth(esp, 1), false) &&
			is_user_vaddr_after(esp, 1, int)) {
		syscall_return = filesize_handler(get_arg(esp, 1, int));
	} else if (syscall_number == SYS_WRITE &&
			is_valid_user_addr(kth(esp, 1), false) &&
			is_user_vaddr_after(esp, 1, int) &&
			is_valid_user_addr(kth(esp, 2), false) &&
			is_user_vaddr_after(esp, 2, char*) &&
			is_valid_user_addr(kth(esp, 3), false) &&
			is_user_vaddr_after(esp, 3, unsigned)) {
		syscall_return = write_handler(get_arg(esp, 1, int), get_arg(esp, 2, char*), get_arg(esp, 3, unsigned));
	} else if (syscall_number == SYS_READ &&
			is_valid_user_addr(kth(esp, 1), false) &&
			is_user_vaddr_after(esp, 1, int) &&
			is_valid_user_addr(kth(esp, 2), true) &&
			is_user_vaddr_after(esp, 2, char*) &&
			is_valid_user_addr(kth(esp, 3), false) &&
			is_user_vaddr_after(esp, 3, unsigned)) {
		syscall_return = read_handler(get_arg(esp, 1, int), get_arg(esp, 2, char*), get_arg(esp, 3, unsigned));
	} else if (syscall_number == SYS_EXEC &&
			is_valid_user_addr(kth(esp, 1), false) &&
			is_user_vaddr_after(esp, 1, char*)) {
		syscall_return = exec_handler(get_arg(esp, 1, char*));
	} else if (syscall_number == SYS_WAIT &&
			is_valid_user_addr(kth(esp, 1), false) &&
			is_user_vaddr_after(esp, 1, pid_t)) {
		syscall_return = wait_handler(get_arg(esp, 1, pid_t));
	} else if (syscall_number == SYS_HALT) {
		halt_handler();
	} else if (syscall_number == SYS_FIBO &&
			is_valid_user_addr(kth(esp, 1), false) &&
			is_user_vaddr_after(esp, 1, int)) {
		syscall_return = fibonacci(get_arg(esp, 1, int));
	} else if (syscall_number == SYS_FOURSUM &&
			is_valid_user_addr(kth(esp, 1), false) &&
			is_user_vaddr_after(esp, 1, int) &&
			is_valid_user_addr(kth(esp, 2), false) &&
			is_user_vaddr_after(esp, 2, int) &&
			is_valid_user_addr(kth(esp, 3), false) &&
			is_user_vaddr_after(esp, 3, int) &&
			is_valid_user_addr(kth(esp, 4), false) &&
			is_user_vaddr_after(esp, 4, int)) {
		syscall_return = sum_of_four_integers(get_arg(esp, 1, int), get_arg(esp, 2, int), get_arg(esp, 3, int), get_arg(esp, 4, int));
	} else if (syscall_number == SYS_MMAP &&
			is_valid_user_addr(kth(esp, 1), false) &&
			is_user_vaddr_after(esp, 1, int) &&
			is_valid_user_addr(kth(esp, 2), false) &&
			is_user_vaddr_after(esp, 2, char*)) {
		syscall_return = mmap_handler(get_arg(esp, 1, int), get_arg(esp, 2, char*));
	} else if (syscall_number == SYS_MUNMAP &&
			is_valid_user_addr(kth(esp, 1), false) &&
			is_user_vaddr_after(esp, 1, int)) {
		munmap_handler(get_arg(esp, 1, int));
	} else { /* Not implemented call or invalid call. */
		exit_handler(-1);
	}
}
#undef kth
#undef get_arg
#undef is_user_vaddr_after
#undef SYSTEMCALL_HANDLER_LIST
#undef syscall_return

static void
exit_handler (int status)
{
	thread_current() -> exit_code = status;
	thread_exit();
}

static bool
remove_handler (const char *file_name)
{
	if (!is_user_vaddr(file_name) ||
		!is_valid_user_addr(file_name, false) ||
		!is_valid_user_addr(file_name+(strlen(file_name) ? strlen(file_name)-1 : 0), false))
		exit_handler(-1);

	return filesys_remove(file_name);
}

static bool
create_handler (const char *file_name, unsigned initial_size)
{
	if (!is_user_vaddr(file_name) ||
		!is_valid_user_addr(file_name, false) ||
		!is_valid_user_addr(file_name+(strlen(file_name) ? strlen(file_name)-1 : 0), false))
		exit_handler(-1);

	uint8_t *buf = (uint8_t*)((unsigned)file_name / PGSIZE * PGSIZE);
	is_valid_user_addr(buf, true);
	struct hash_elem *h = frame_find_upage(&thread_current() -> frame_table,
			(uint8_t*)((unsigned)buf/PGSIZE*PGSIZE));
	if (h)
		hash_entry(h, struct frame_entry, all_elem) -> pinned = true;

	int ret = filesys_create(file_name, initial_size);
	hash_entry(h, struct frame_entry, all_elem) -> pinned = false;
	return ret;
}

#define MAX_FILE_PER_THREAD 32
static int
open_handler (const char *file_name)
{
	if (!is_user_vaddr(file_name) ||
		!is_valid_user_addr(file_name, false) ||
		!is_valid_user_addr(file_name+(strlen(file_name) ? strlen(file_name)-1 : 0), false))
		exit_handler(-1);

	struct file *fp = NULL;
	struct fdesc *new_open = NULL;
	int new_fd = 0;

	if (list_size(&thread_current() -> files) + 2 >= MAX_FILE_PER_THREAD) {
		return -1;
	}

	lock_acquire(&file_access_lock);
	if ((fp = filesys_open(file_name)) != NULL) {
		new_open = malloc(sizeof(*new_open));
		new_open -> file = fp;
		new_fd = thread_current() -> last_fd++;
		new_open -> fd = new_fd;
		list_push_back(&thread_current() -> files, &new_open -> elem);
		lock_release(&file_access_lock);
		return new_fd;
	} else {
		lock_release(&file_access_lock);
		return -1;
	}
}
#undef MAX_FILE_PER_THREAD

/* Function-ize repeated iteration. */
static struct list_elem *find_file_from_thread(int fd);

static struct list_elem *
find_file_from_thread(int fd)
{
	struct list_elem *iter = NULL;
	for (iter = list_begin(&thread_current() -> files);iter != list_end(&thread_current() -> files); iter = list_next(iter)) {
		struct fdesc *entry = list_entry(iter, struct fdesc, elem);
		if (entry -> fd == fd) return iter;
	}

	return NULL;
}

static void
close_handler (int fd)
{
	struct list_elem *iter = NULL;
	struct fdesc *entry = NULL;
	/* Do not close invalid(or std-in/out) files! */
	if (fd < 2) return;

	iter = find_file_from_thread(fd);

	if (iter != NULL) {
		list_remove(iter);
		entry = list_entry(iter, struct fdesc, elem);
		file_close(entry -> file);
		free(entry);
	}

	return;
}

static int
filesize_handler (int fd)
{
	struct list_elem *iter = find_file_from_thread(fd);
	struct fdesc *entry = NULL;
	int file_len = 0;
	if (iter == NULL) return -1;

	entry = list_entry(iter, struct fdesc, elem);
	lock_acquire(&file_access_lock);
	file_len = file_length(entry -> file);
	lock_release(&file_access_lock);
	return file_len;
}

static void
seek_handler (int fd, unsigned position)
{
	struct list_elem *iter = find_file_from_thread(fd);
	struct fdesc *entry = NULL;
	if (iter == NULL) return;

	entry = list_entry(iter, struct fdesc, elem);
	file_seek(entry -> file, position);
}

static unsigned
tell_handler (int fd)
{
	struct list_elem *iter = find_file_from_thread(fd);
	struct fdesc *entry = NULL;
	if (iter == NULL) return 0;

	entry = list_entry(iter, struct fdesc, elem);
	return file_tell(entry -> file);
}

static int
write_handler (int fd, const void *buffer, unsigned size)
{
	if (!is_user_vaddr(buffer) ||
		!is_user_vaddr(buffer+(size > 0 ? size-1 : 0)) ||
		!is_valid_user_addr(buffer, false))
		exit_handler(-1);

	int bytes_written = 0;
	if (fd == 1) {
		putbuf(buffer, size);
		bytes_written = size;
	} else {
		lock_acquire(&file_access_lock);
		struct list_elem *iter = find_file_from_thread(fd);
		struct fdesc *entry = NULL;
		if (iter == NULL) {
			lock_release(&file_access_lock);
			return -1;
		}

		uint8_t *buf = (uint8_t*)((unsigned)buffer / PGSIZE * PGSIZE);
		int size_left = (size + PGSIZE - 1) / PGSIZE * PGSIZE + (size % PGSIZE == 0 ? PGSIZE : 0),
			buf_ptr = 0;

		while (size_left > 0) {
			if (is_valid_user_addr(buf + buf_ptr, true)) {
				struct hash_elem *h = frame_find_upage(&thread_current() -> frame_table,
										(uint8_t*)((unsigned)buf/PGSIZE*PGSIZE) + buf_ptr);
				if (h)
					hash_entry(h, struct frame_entry, all_elem) -> pinned = true;
			}
			buf_ptr += PGSIZE;
			size_left -= PGSIZE;
		}

		entry = list_entry(iter, struct fdesc, elem);
		bytes_written = file_write(entry->file, buffer, size);

		size_left = (size + PGSIZE - 1) / PGSIZE * PGSIZE + (size % PGSIZE == 0 ? PGSIZE : 0);
		buf_ptr = 0;

		while (size_left > 0) {
			if (is_valid_user_addr(buf + buf_ptr, true)) {
				struct hash_elem *h = frame_find_upage(&thread_current() -> frame_table,
										(uint8_t*)((unsigned)buf/PGSIZE*PGSIZE) + buf_ptr);
				if (h)
					hash_entry(h, struct frame_entry, all_elem) -> pinned = false;
			}
			buf_ptr += PGSIZE;
			size_left -= PGSIZE;
		}

		lock_release(&file_access_lock);
	}

	return bytes_written;
}

static int
read_handler (int fd, void *buffer, unsigned size)
{
	if (!is_user_vaddr(buffer) ||
		!is_user_vaddr(buffer+(size > 0 ? size-1 : 0)) ||
		!is_valid_user_addr(buffer, true) ||
		!is_valid_user_addr(buffer + size, true))
		exit_handler(-1);

	int bytes_read = 0;
	uint8_t *buf = (uint8_t*)((unsigned)buffer / PGSIZE * PGSIZE);
	if (fd == 0) {
		input_init();
		while (size > 0) {
			*buf = input_getc();
			++buf;
			++bytes_read;
			--size;
		}
	} else {
		lock_acquire(&file_access_lock);
		struct list_elem *iter = find_file_from_thread(fd);
		struct fdesc *entry = NULL;
		if (iter == NULL) {
			lock_release(&file_access_lock);
			return -1;
		}

		int size_left = (size + PGSIZE - 1) / PGSIZE * PGSIZE + (size % PGSIZE == 0 ? PGSIZE : 0),
			buf_ptr = 0;

		while (size_left > 0) {
			if (is_valid_user_addr(buf + buf_ptr, true)) {
				struct hash_elem *h = frame_find_upage(&thread_current() -> frame_table,
										(uint8_t*)((unsigned)buf/PGSIZE*PGSIZE) + buf_ptr);
				if (h)
					hash_entry(h, struct frame_entry, all_elem) -> pinned = true;
			}
			buf_ptr += PGSIZE;
			size_left -= PGSIZE;
		}

		entry = list_entry(iter, struct fdesc, elem);
		bytes_read = file_read(entry->file, buffer, size);

		size_left = (size + PGSIZE - 1) / PGSIZE * PGSIZE + (size % PGSIZE == 0 ? PGSIZE : 0);
		buf_ptr = 0;

		while (size_left > 0) {
			if (is_valid_user_addr(buf + buf_ptr, true)) {
				struct hash_elem *h = frame_find_upage(&thread_current() -> frame_table,
										(uint8_t*)((unsigned)buf/PGSIZE*PGSIZE) + buf_ptr);
				if (h)
					hash_entry(h, struct frame_entry, all_elem) -> pinned = false;
			}
			buf_ptr += PGSIZE;
			size_left -= PGSIZE;
		}

		lock_release(&file_access_lock);
	}

	return bytes_read;
}

static pid_t
exec_handler (const char *cmd_line)
{
	if (!is_user_vaddr(cmd_line) ||
		!is_valid_user_addr(cmd_line, false) ||
		!is_valid_user_addr(cmd_line+(strlen(cmd_line) ? strlen(cmd_line)-1 : 0), false))
		exit_handler(-1);

	return process_execute(cmd_line);
}

static int
wait_handler (pid_t pid)
{
	return process_wait(pid);
}

static void
halt_handler (void)
{
	shutdown_power_off();
}

/* These are not real syscalls.. */
static int
fibonacci (int n)
{
	// Init p = F_0, q = F_1.
	int p = 0, q = 1, r;

	while (n --> 0) {
		r = q;
		q += p;
		p = r;
	}

	return p;
}

static int
sum_of_four_integers (int a, int b, int c, int d)
{
	return a + b + c + d;
}

/* Function-ize repeated iteration. */
static struct list_elem *find_map_from_thread(int md);

static struct list_elem *
find_map_from_thread(int md)
{
	struct list_elem *iter = NULL;
	for (iter = list_begin(&thread_current() -> maps);
		 iter != list_end(&thread_current() -> maps); iter = list_next(iter)) {
		struct mdesc *entry = list_entry(iter, struct mdesc, elem);
		if (entry -> md == md) return iter;
	}

	return NULL;
}

static int 
mmap_handler (int fd, uint8_t *upage)
{
	lock_acquire(&mmap_access_lock);
	/* You can't map stdin/out, you can map only opened files. */
	if (fd < 2 || fd >= thread_current() -> last_fd) {
		lock_release(&mmap_access_lock);
		return -1;
	}

	int mmap_length = filesize_handler(fd),
		mmap_npages = (mmap_length + PGSIZE - 1) / PGSIZE;

	/* It must be page-aligned, and fit into the virtual address region. */
	if ((unsigned)upage != (unsigned)upage / PGSIZE * PGSIZE || upage + mmap_npages * PGSIZE >= PHYS_BASE) {
		lock_release(&mmap_access_lock);
		return -1;
	}

	/* It can't be mapped on stack region. */
	if (STACK_LIMIT <= upage && upage + mmap_npages * PGSIZE < PHYS_BASE) {
		return -1;
	}

	int left_length = mmap_length,
		offset = 0, backup_offset = 0;
	uint8_t *upage_ptr = upage;
	struct list_elem *e = find_file_from_thread(fd);
	struct fdesc* fdesc = NULL;

	/* zero-sized file, or non-existing file. */
	if (e == NULL || mmap_npages < 1 || mmap_length < 1) {
		lock_release(&mmap_access_lock);
		return -1;
	}

	fdesc = list_entry(e, struct fdesc, elem);
	backup_offset = file_tell(fdesc -> file);

	/* Check whether the memory region is assigned to another page or not. */
	int i;
	for (i = 0; i < mmap_npages; i++) {
		if (supp_page_find(&thread_current() -> supp_page_table, upage + PGSIZE * i)) {
			lock_release(&mmap_access_lock);
			return -1;
		}
	}

	/* Reached here because the memory regions are seems to be legal. */
	while (left_length > 0) {
		/* Push entries to the supplemental page table, one by one. */
		supp_page_insert(&thread_current() -> supp_page_table, upage_ptr, fdesc -> file, offset,
				left_length >= PGSIZE ? PGSIZE : left_length, false, true);
		left_length -= PGSIZE;
		upage_ptr += PGSIZE;
		offset += PGSIZE;
	}
	file_seek(fdesc -> file, backup_offset);

	/* Push this record to the list. */
	struct mdesc *new_md = malloc(sizeof *new_md);
	new_md -> md = thread_current() -> last_md++;
	new_md -> file = fdesc -> file;
	new_md -> upage = upage;
	new_md -> length = mmap_length;
	list_push_back(&thread_current() -> maps, &new_md -> elem);

	lock_release(&mmap_access_lock);
	return new_md -> md;
}

void
munmap_handler (int md)
{
	lock_acquire(&mmap_access_lock);

	struct list_elem *e = find_map_from_thread(md);
	if (e == NULL) {
		lock_release(&mmap_access_lock);
		return;
	}

	struct mdesc *mdesc = list_entry(e, struct mdesc, elem);
	list_remove(e);

	int mmap_npages = (mdesc -> length + PGSIZE - 1) / PGSIZE,
		offset = 0, backup_offset = file_tell(mdesc -> file),
		left_size = mdesc -> length;
	uint8_t *upage_ptr = mdesc -> upage;

	/* Write contents back to the file. */
	lock_acquire(&file_access_lock);
	while (left_size > 0) {
		is_valid_user_addr(upage_ptr, true);
		file_write_at(mdesc -> file, upage_ptr, left_size < PGSIZE ? left_size : PGSIZE, offset);
		left_size -= PGSIZE;
		upage_ptr += PGSIZE;
		offset += PGSIZE;
	}
	file_seek(mdesc -> file, backup_offset);
	lock_release(&file_access_lock);

	free(mdesc);
	lock_release(&mmap_access_lock);
}
#undef STACK_LIMIT
