all: ssh2crack

CC	= gcc
CFLAGS	= -g

.c.o: 	$(CC) $(CFLAGS) \
	-c -o $*.o $<

OBJS = 	ssh2crack.o crack_engine.o ssh.o libsock.o slab.o

ssh2crack: $(OBJS)
	$(CC) -o ssh2crack $(OBJS) -lssh -lssh_threads -lpthread

clean:
	rm -f ssh2crack *.o
