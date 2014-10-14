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
static int get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);

//Syscall Handlers.
static void exit_handler (int status);
static int write_handler (int fd, const void *buffer, unsigned size);
static int read_handler (int fd, void *buffer, unsigned size);
static void halt_handler (void);
static pid_t exec_handler (const char *cmd_line);
static int wait_handler (pid_t pid);

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

#define get_arg(esp,k,type) *(type*)(esp + k*sizeof(type*))
#define SYSTEMCALL_HANDLER_LIST 0
#define syscall_return (f->eax) 
static void
syscall_handler (struct intr_frame *f) 
{
	char *esp = f -> esp;
	int syscall_number = -1;

	if (is_user_vaddr(esp)) {
		syscall_number = *(int*)esp;
	}

	if (SYSTEMCALL_HANDLER_LIST) {
	} else if (syscall_number == SYS_EXIT) {
		exit_handler(get_arg(esp, 1, int));
	} else if (syscall_number == SYS_WRITE) {
		syscall_return = write_handler(get_arg(esp, 1, int), get_arg(esp, 2, char*), get_arg(esp, 3, unsigned));
	} else if (syscall_number == SYS_READ) {
		syscall_return = read_handler(get_arg(esp, 1, int), get_arg(esp, 2, char*), get_arg(esp, 3, unsigned));
	} else if (syscall_number == SYS_EXEC) {
		syscall_return = exec_handler(get_arg(esp, 1, char*));
	} else if (syscall_number == SYS_WAIT) {
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
	if (!is_user_vaddr(buffer)) return -1;
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
	if (!is_user_vaddr(buffer)) return -1;
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
	if (!is_user_vaddr(cmd_line)) return -1;
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
