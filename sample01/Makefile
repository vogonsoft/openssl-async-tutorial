LDFLAGS += -levent

all: build
build: client

clean:
	rm -rf *.o
	rm -rf client

rebuild: clean build

client: client.o
	$(CC) -o $@ $^ $(LDFLAGS)

