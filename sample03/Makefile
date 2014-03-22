LDFLAGS += -levent -lssl -lcrypto
CFLAGS += -g -Wall

all: build
build: client

clean:
	rm -rf *.o
	rm -rf client

rebuild: clean build

client: client.o buffer.o sslbuffer.o
	$(CC) -o $@ $^ $(LDFLAGS)

