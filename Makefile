all: skpd

#dietlibc: dietlibc/bin/diet

#dietlibc/bin/diet:
#	cd dietlibc; make
#	cd dietlibc; ln -s bin-* bin
#
skpd: src/skpd.c
	cd src;	make
	mv src/skpd .

clean:
	cd src; make clean
#	cd dietlibc; make clean
#	cd dietlibc; rm -f bin
	rm -f skpd
