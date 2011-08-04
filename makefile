CC=g++
DEBUG=-g
LFLAGS=-Wall $(DEBUG)
CFLAGS=-Wall -c $(DEBUG)
DEPS=AES.o main.o

all: AES

AES: $(DEPS)
	$(CC) $(DEBUG) $(DEPS) -o AES

%.o: %.cpp %.h
	$(CC) $(CFLAGS) $<

clean:
	rm -rf *.o *~ *.encrypted *.decrypted AES
