CC  =   ../dietlibc/bin/diet gcc
CFLAGS = -Wall -fno-builtin -O2 -I../include -fomit-frame-pointer -nostdinc -DNODIETREF -I../../dietlibc/include $(EXTRA_CFLAGS)
LDFLAGS = -s

skpd: skpd.c
	$(CC) $(CFLAGS) $(LDFLAGS) -g -Wall skpd.c -o skpd

clean:
	rm -f skpd
