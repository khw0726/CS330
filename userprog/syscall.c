#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);
static int get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);

//Syscall Handlers.
static void exit_handler (int status);
static void write_handler (int fd, const void *buffer, unsigned size);

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
static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	char *esp = f -> esp;
	const int syscall_number = *(int*)esp;

	if (syscall_number == SYS_EXIT) {
		exit_handler(get_arg(esp, 1, int));
	} else if (syscall_number == SYS_WRITE) {
		write_handler(get_arg(esp, 1, int), get_arg(esp, 2, char*), get_arg(esp, 3, unsigned));
	}
}

static void
exit_handler (int status)
{
	thread_current()->exit_code = status;
	thread_exit ();
}

static void
write_handler (int fd, const void *buffer, unsigned size)
{
	if (fd == 1) {
		putbuf(buffer, size);
	} else {
		/* Not implemented. */
		return -1;
	}
}

