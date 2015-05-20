CFLAGS=-g3 -O0

a.out: rd.o vhost_memmap.o
	gcc $(CFLAGS) -o $@ $^
