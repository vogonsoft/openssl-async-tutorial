#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/dns.h>

#include <openssl/ssl.h>

#include "buffer.h"
#include "sslbuffer.h"

#define CIPHER_LIST "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH"

void err_exit(char *str, ...)
{
	va_list ap;
	va_start(ap, str);
	vprintf(str, ap);
	va_end(ap);
	exit(-1);
}

/* Callbacks */
void console_func(evutil_socket_t fd, short event, void *arg);

struct user_data {
	char *name; /* the name we're resolving */
	struct event_base *base;
	int write; /* Socket ready for writing? */
	struct sslbuffer_t *sslbuffer;
};

void sslreadcb(
	struct sslbuffer_t *sslbuffer,
	uint8_t *data,
	size_t size,
	void *ctx);

void ssleventcb(struct sslbuffer_t *sslbuffer, int event, void *ctx);

int
main(int argc, char **argv)
{
	char *host;
	char *port;
	struct event_base *base;
	struct event *ev1;
	int res;
	struct user_data *user_data;
	struct sslbuffer_t *sslbuffer = NULL;
	SSL_CTX *ctx = NULL;

	base = event_base_new();
	if (!base)
		err_exit("Error creating event_base!\n");
	
	SSL_library_init();
	SSL_load_error_strings();
	
	ctx = SSL_CTX_new(SSLv23_method());
	if (ctx == NULL)
		goto End;
    SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 |
    	SSL_OP_NO_SSLv3);

	res = SSL_CTX_set_default_verify_paths(ctx);
	if (res != 1)
		goto End;
	
	sslbuffer = SSLBufferCreate(ctx, base);
	if (sslbuffer == NULL)
		goto End;

	if (argc < 3)
	{
		fprintf(stderr, "Usage: client <host> <port>\n");
		exit(0);
	}
	host = argv[1];
	port = argv[2];
	printf("Connecting to %s:%s\n", host, port);

	if (!(user_data = malloc(sizeof(struct user_data))))
		err_exit("malloc");
	user_data->name = strdup(host);
	if (user_data->name == NULL)
		err_exit("strdup");
	user_data->base = base;
	user_data->sslbuffer = sslbuffer;

	ev1 = event_new(base, 0, EV_READ|EV_PERSIST, console_func, user_data);
	res = event_add(ev1, NULL);
	if (res != 0)
		err_exit("Error: %d", res);

	res = SSLBufferConnect(sslbuffer, host, port);
	if (!res)
		err_exit("Error connecting to the server");

	SSLBufferSetCB(
		sslbuffer,
		sslreadcb,
		ssleventcb,
		user_data);

	/* Run the event loop. */
	event_base_dispatch(base);
	
End:
	printf("Exiting client\n");
	if (user_data != NULL)
	{
		free(user_data->name);
		free(user_data);
	}
	event_base_free(base);
	if (sslbuffer != NULL)
		SSLBufferDelete(sslbuffer);
	if (ctx != NULL)
		SSL_CTX_free(ctx);

	return 0;
}

void console_func(evutil_socket_t fd, short event, void *arg)
{
	struct user_data *data = (struct user_data *) arg;
	ssize_t size;
	static char buffer[128];
	static char buffer2[256];
	
	if (event & EV_READ)
	{
		size = read(fd, buffer, sizeof(buffer));
		if (size > 0)
		{
			if (buffer[size-1] == '\n')
			{
				buffer2[0] = '\0';
				buffer[size-1] = '\0';
				strcat(buffer2, buffer);
				strcat(buffer2, "\r\n");
				size += 1;
			}
			SSLBufferWrite(data->sslbuffer, (uint8_t *) buffer2, size);
		}
	}
}

void sslreadcb(
	struct sslbuffer_t *sslbuffer,
	uint8_t *data,
	size_t size,
	void *ctx)
{
	struct user_data *user_data;
	uint8_t buffer[256];
	size_t bufsize;
	uint8_t *srcdata;

	user_data = (struct user_data *) ctx;

	srcdata = (uint8_t *) data;
	while (size > 0)
	{
		bufsize = size;
		if (bufsize + 1 > sizeof(buffer))
			bufsize = sizeof(buffer) - 1;
		memcpy(buffer, srcdata, bufsize);
		buffer[bufsize] = '\0';
		printf("%s", buffer);
		size -= bufsize;
		srcdata += bufsize;
	}
}

void ssleventcb(struct sslbuffer_t *sslbuffer, int event, void *ctx)
{
	struct user_data *user_data;

	user_data = (struct user_data *) ctx;

	printf("ssleventcb: got event=%d\n", event);
	switch (event)
	{
		case EVT_CONNECTED:
			printf("Connected\n");
			break;
		default:
			printf("ssleventcb: unrecognized event: %d\n", event);
			break;
	}
}

