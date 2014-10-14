#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "devices/input.h"
typedef int pid_t;

static void syscall_handler (struct intr_frame *);
static bool is_valid_user_addr (const uint8_t *uaddr);
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
static int sum_of_four_digits (int a, int b, int c, int d);

/* Returns true if uaddr is valid user memory.
   this function should called before dereference. */
static bool
is_valid_user_addr (const uint8_t *uaddr)
{
	if (uaddr >= PHYS_BASE) return false;
	if (pagedir_get_page(thread_current()->pagedir, uaddr) == NULL)
		return false;
	return true;
}

/* Reads a byte at user virtual address UADDR.
 * UADDR must be below PHYS_BASE.
 * Returns the byte value if successful, -1 if a segfault occured. */
static int
get_user (const uint8_t *uaddr)
{
	int result;
	asm ("movl $1f, %0; movzbl %1, %0; 1:" : "=&a" (result) : "m" (*uaddr));
	return result;
}

/* Writes BYTE to user address UDST.
 * UDST must be below PHYS_BASE.
 * Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
	int error_code;
	asm ("movl $1f, %0; movb %2, %1; 1:" : "=&a" (error_code), "=m" (*udst) : "q" (byte));
	return error_code != -1;
}

void
syscall_init (void) 
{
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

	//printf("esp: %p. this is %s.\n", esp, is_valid_user_addr(esp) ? "valid" : "invalid");
	if (is_valid_user_addr(esp) &&
		is_user_vaddr_after(esp, 0, int)) {
		syscall_number = *(int*)esp;
	}

	if (SYSTEMCALL_HANDLER_LIST) {
	} else if (syscall_number == SYS_EXIT &&
			is_user_vaddr_after(esp, 1, int) &&
			is_valid_user_addr(kth(esp, 1))) {
		exit_handler(get_arg(esp, 1, int));
	} else if (syscall_number == SYS_WRITE &&
			is_valid_user_addr(kth(esp, 1)) &&
			is_user_vaddr_after(esp, 1, int) &&
			is_valid_user_addr(kth(esp, 2)) &&
			is_user_vaddr_after(esp, 2, char*) &&
			is_valid_user_addr(kth(esp, 3)) &&
			is_user_vaddr_after(esp, 3, unsigned)) {
		syscall_return = write_handler(get_arg(esp, 1, int), get_arg(esp, 2, char*), get_arg(esp, 3, unsigned));
	} else if (syscall_number == SYS_READ &&
			is_valid_user_addr(kth(esp, 1)) &&
			is_user_vaddr_after(esp, 1, int) &&
			is_valid_user_addr(kth(esp, 2)) &&
			is_user_vaddr_after(esp, 2, char*) &&
			is_valid_user_addr(kth(esp, 3)) &&
			is_user_vaddr_after(esp, 3, unsigned)) {
		syscall_return = read_handler(get_arg(esp, 1, int), get_arg(esp, 2, char*), get_arg(esp, 3, unsigned));
	} else if (syscall_number == SYS_EXEC &&
			is_valid_user_addr(kth(esp, 1)) &&
			is_user_vaddr_after(esp, 1, char*)) {
		syscall_return = exec_handler(get_arg(esp, 1, char*));
	} else if (syscall_number == SYS_WAIT &&
			is_valid_user_addr(kth(esp, 1)) &&
			is_user_vaddr_after(esp, 1, pid_t)) {
		syscall_return = wait_handler(get_arg(esp, 1, pid_t));
	} else if (syscall_number == SYS_HALT) {
		halt_handler();
	} else { /* Not implemented call or invalid call. */
		exit_handler(-1);
	}
}

static void
exit_handler (int status)
{
	thread_current() -> exit_code = status;
	thread_exit();
}

static int
write_handler (int fd, const void *buffer, unsigned size)
{
	if (!is_user_vaddr(buffer) ||
		!is_user_vaddr(buffer+(size > 0 ? size-1 : 0)) ||
		!is_valid_user_addr(buffer))
		exit_handler(-1);

	int bytes_written = 0;
	if (fd == 1) {
		putbuf(buffer, size);
		bytes_written = size;
	} else {
		/* Not implemented. */
		return -1;
	}

	return bytes_written;
}

static int
read_handler (int fd, void *buffer, unsigned size)
{
	if (!is_user_vaddr(buffer) ||
		!is_user_vaddr(buffer+(size > 0 ? size-1 : 0)) ||
		!is_valid_user_addr(buffer))
		exit_handler(-1);

	int bytes_read = 0;
	uint8_t *buf = buffer;
	if (fd == 0) {
		input_init();
		while (size > 0) {
			*buf = input_getc();
			++buf;
			++bytes_read;
			--size;
		}
	} else {
		/* Not implemented. */
		return -1;
	}

	return bytes_read;
}

static pid_t
exec_handler (const char *cmd_line)
{
	if (!is_user_vaddr(cmd_line) ||
		!is_valid_user_addr(cmd_line) ||
		!is_valid_user_addr(cmd_line+(strlen(cmd_line) ? strlen(cmd_line)-1 : 0)))
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

static int
fibonacci (int n)
{
	int p = 0, q = 1, r;

	while (n --> 0) {
		r = q;
		q += p;
		p = r;
	}

	return p;
}

static int
sum_of_four_digits (int a, int b, int c, int d)
{
}
