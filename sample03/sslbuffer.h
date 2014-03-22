#ifndef _sslbuffer_h_
#define _sslbuffer_h_

#include <openssl/ssl.h>
#include <event2/event.h>
#include "buffer.h"

struct sslbuffer_t;

typedef void (*SSLBuffer_read_cb)(
	struct sslbuffer_t *sslbuffer,
	uint8_t *data,
	size_t size,
	void *ctx);

typedef void (*SSLBuffer_event_cb)(struct sslbuffer_t *sslbuffer, int event, void *ctx);

/* Events */
#define EVT_CONNECTED 1


struct sslbuffer_t
{
	struct event_base *base;
	SSL_CTX *ctx;

	void *cb_ctx;
	SSLBuffer_read_cb readcb;
	SSLBuffer_event_cb eventcb;

	SSL *ssl;
	struct event *ev_write;
	struct event *ev_read;
	struct buffer_t *write_buffer_1; /* Buffer to which upper layer writes */
	struct buffer_t *write_buffer_2; /* Buffer for writing to SSL connection */
	int fl_connecting;
	int fl_reading;
	int fl_writing;
	int fl_want_read;
	int fl_want_write;
};

struct sslbuffer_t *SSLBufferCreate(SSL_CTX *ctx, struct event_base *base);
void SSLBufferDelete(struct sslbuffer_t *sslbuffer);

int SSLBufferConnect(struct sslbuffer_t *sslbuffer, const char *host,
	const char *port);

void SSLBuffer_func(evutil_socket_t fd, short event, void *arg);

int SSLBufferSetCB(
	struct sslbuffer_t *sslbuffer,
	SSLBuffer_read_cb readcb,
	SSLBuffer_event_cb eventcb,
	void *ctx);

void SSLBufferWrite(struct sslbuffer_t *sslbuffer, uint8_t *data, size_t size);

void SSLBufferTryWrite(struct sslbuffer_t *sslbuffer);
void SSLBufferTryRead(struct sslbuffer_t *sslbuffer);

#endif /* !_sslbuffer_h_ */

