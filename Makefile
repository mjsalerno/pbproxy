CC = gcc
CFLAGS = -g -Wall #-Werror 
LIBS = -lcrypt -lssl -lpcap
BIN = pbproxy

.PHONY: clean all tags

all: pbproxy

pbproxy: pbproxy.o
	$(CC) $(CFLAGS) -o $(BIN) pbproxy.o $(LIBS)

pbproxy.o: pbproxy.c pbproxy.h
	$(CC) $(CFLAGS) -c pbproxy.c

clean:
	rm -f *.o *.out pbproxy


tags:
	find . -name "*.[chw]" > cscope.files
	ctags -R *
	cscope -b -q -k
	~/git/YCM-Generator/config_gen.py .

