all: main

main: main.o crypto.o
	gcc -o main main.o crypto.o -lssl -lcrypto

main.o: main.c crypto.h
	gcc -c main.c

crypto.o: crypto.c crypto.h
	gcc -c crypto.c

clean:
	rm -f *.o main
