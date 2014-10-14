#include <stdio.h>
#include <stdlib.h>
#include <syscall.h>

int
main (int argc, char *argv[])
{
  int i, a[4];

  for (i = 0; i < 4; i++) a[i] = atoi(argv[i+1]);
  printf ("%d %d\n", pibonacci(a[0]), sum_of_four_integers(a[0], a[1], a[2], a[3]));

  return 0;
}
