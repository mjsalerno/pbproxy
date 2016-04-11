CC = gcc
CFLAGS = -g -Wall -Werror 
LIBS = -lm -lcrypto -lssl
BIN = pbproxy

.PHONY: clean all tags

all: pbproxy

pbproxy: pbproxy.o encryption.o
	$(CC) $(CFLAGS) -o $(BIN) pbproxy.o encryption.o $(LIBS)

pbproxy.o: pbproxy.c pbproxy.h
	$(CC) $(CFLAGS) -c pbproxy.c
	
encryption.o: encryption.c encryption.h
	$(CC) $(CFLAGS) -c encryption.c

clean:
	rm -f *.o *.out pbproxy


tags:
	find . -name "*.[chw]" > cscope.files
	ctags -R *
	cscope -b -q -k
	~/git/YCM-Generator/config_gen.py .

