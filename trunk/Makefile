tclgpg.so: tclgpg.o
	gcc -shared -o tclgpg.so tclgpg.o -L/usr/lib -ltclstub8.4

tclgpg.o: tclgpg.c
	gcc -I/usr/include/tcl -o tclgpg.o -c tclgpg.c

