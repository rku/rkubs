CC=gcc
LIBS=-lcrypto
CFLAGS=-DWITH_ANSI_ESCAPE_SEQ -Wall

EXEC=rkubs
OBJS=rkubs.o

$(EXEC): $(OBJS)
	$(CC) -o $(EXEC) $(OBJS) $(LIBS)

clean:
	rm -f *.o $(EXEC)

install:
	install $(EXEC) /usr/games/

