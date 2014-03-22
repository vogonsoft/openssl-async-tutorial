LDFLAGS += -levent -lssl -lcrypto
CFLAGS += -g -O0

all: build
build: client

clean:
	rm -rf *.o
	rm -rf client

rebuild: clean build

client: client.o buffer.o
	$(CC) -o $@ $^ $(LDFLAGS)
