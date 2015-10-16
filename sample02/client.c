#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/dns.h>

#include "buffer.h"

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
void sock_cb(evutil_socket_t fd, short what, void *arg);

struct user_data {
	char *name; /* the name we're resolving */
	struct event_base *base;
	struct buffer_t *buffer;
	evutil_socket_t sock;
	int write; /* Socket ready for writing? */
	struct event *evwrite;
};

int
main(int argc, char **argv)
{
	char *host;
	int port;
	char *service;
	struct event_base *base;
	struct event *ev1, *ev2;
	int res;
	struct evutil_addrinfo hints;
	struct user_data *user_data;
	evutil_socket_t sock;
	struct evutil_addrinfo *answer = NULL;
	struct buffer_t *buffer;
	
	buffer = BufferCreate(16);
	if (buffer == NULL)
		goto End;

	printf("Hello from letls client\n");
	if (argc < 3)
	{
		fprintf(stderr, "Usage: client <host> <port>\n");
		exit(0);
	}
	host = argv[1];
	port = atoi(argv[2]);
	service = argv[2];
	printf("Connecting to %s:%d\n", host, port);

	base = event_base_new();
	if (!base)
		err_exit("Error creating event_base!\n");
	
	if (!(user_data = malloc(sizeof(struct user_data))))
		err_exit("malloc");
	if (!(user_data->name = strdup(host)))
		err_exit("strdup");
	user_data->base = base;
	
	user_data->buffer = buffer;

	ev1 = event_new(base, 0, EV_READ|EV_PERSIST, console_func, user_data);
	res = event_add(ev1, NULL);
	if (res != 0)
		err_exit("Error: %d", res);

	/* Build the hints to tell getaddrinfo how to act. */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC; /* v4 or v6 is fine. */
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP; /* We want a TCP socket */

	/* Only return addresses we can use. */
	hints.ai_flags = EVUTIL_AI_ADDRCONFIG;

    /* Look up the hostname. Note that this is done in a blocking call. If
       we want a nonblocking name resolution, we should use evdns_getaddrinfo.
     */
    res = evutil_getaddrinfo(host, service, &hints, &answer);
    if (res != 0) {
          err_exit("Error while resolving '%s': %s",
                  host, evutil_gai_strerror(res));
          return -1;
    }

	sock = socket(answer->ai_family,
		answer->ai_socktype,
		answer->ai_protocol);
	if (sock < 0)
		return -1;
	if (connect(sock, answer->ai_addr, answer->ai_addrlen)) {
		/* Note that we're doing a blocking connect in this function.
		* If this were nonblocking, we'd need to treat some errors
		* (like EINTR and EAGAIN) specially. */
		EVUTIL_CLOSESOCKET(sock);
		return -1;
	}

	evutil_make_socket_nonblocking(sock);
	user_data->sock = sock;

	ev2 = event_new(base, sock, EV_READ | EV_PERSIST,
		sock_cb, user_data);
	res = event_add(ev2, NULL);


	user_data->evwrite = event_new(base, sock,  EV_WRITE,
		sock_cb, user_data);
	res = event_add(user_data->evwrite, NULL);


	/* Run the event loop. */
	event_base_dispatch(base);
	
	/* After the event loop, exit. */
End:
	printf("Exiting client\n");
	free(user_data->name);
	free(user_data);
	event_base_free(base);
	BufferDelete(buffer);

	return 0;
}

void console_func(evutil_socket_t fd, short event, void *arg)
{
	struct user_data *data = (struct user_data *) arg;
	ssize_t size;
	static char buffer[128];
	static char buffer2[256];
	ssize_t n;
	
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
			}
			BufferPush(data->buffer, buffer2, strlen(buffer2));
			if (data->write)
			{
				size = BufferSize(data->buffer);
				BufferPeek(data->buffer, buffer, size);
				n = write(data->sock, buffer, size);
				if (n > 0)
				{
					BufferRemove(data->buffer, (size_t) n);
					data->write = 0;
				}
				event_add(data->evwrite, NULL);
			}
		}
	}
}

void sock_cb(evutil_socket_t fd, short event, void *arg)
{
	struct user_data *data = (struct user_data *) arg;
	uint8_t buffer[256];
	char buffer2[260];
	ssize_t n;

	/* printf("sock_cb: got event %d\n", event); */
	if (event & EV_READ)
	{
		while (1)
		{
			n = read(data->sock, buffer, sizeof(buffer));
			if (n <= 0)
			{
				printf("read returned error: %s\n", strerror(n));
				event_base_loopbreak(data->base);
				return;
			}
			memcpy(buffer2, buffer, n);
			buffer2[n] = '\0';
			printf("%s\n", buffer2);
		}
	}
	else if (event & EV_WRITE)
	{
		size_t size = BufferSize(data->buffer);
		if (size > 0)
		{
			if (size > sizeof(buffer))
				size = sizeof(buffer);
			BufferPeek(data->buffer, buffer, size);
			n = write(data->sock, buffer, size);
			if (n > 0)
			{
				BufferRemove(data->buffer, (size_t) n);
				data->write = 0;
				event_add(data->evwrite, NULL);
			}
			else
			{
				printf("write returned error: %s\n", strerror(n));
				event_base_loopbreak(data->base);
				return;
			}
		}
		else
			data->write = 1; /* Socket ready for writing. */
	}
	else
		printf("%s:%d: got event %hu\n", __FILE__, __LINE__, event);
}

