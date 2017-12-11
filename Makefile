all: sndaemon

sndaemon: daemon.o rbtree.o 
	gcc daemon.o rbtree.o -lpthread -o sndaemon

daemon.o: daemon.c
	gcc -c daemon.c

rbtree.o: rbtree.c
	gcc -c rbtree.c

clean:
	rm -rf *.o sndaemon

