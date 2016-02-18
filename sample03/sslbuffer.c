#include "sslbuffer.h"
#include <stdlib.h>
#include <string.h>
#include <openssl/err.h>

#define CIPHER_LIST "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH"

void print_errors(void)
{
	int flags, line;
	const char *data, *file;
	unsigned long code;
	char str[1024];
	char *errstr;

	code = ERR_get_error_line_data(&file, &line, &data, &flags);
	while (code)
	{
		printf("error code; %lu in %s line %d.\n", code, file, line);
		if (data && (flags & ERR_TXT_STRING))
		printf("error data: %s\n", data);
		code = ERR_get_error_line_data(&file, &line, &data, &flags);
		errstr = ERR_error_string(code, str);
		printf(" (%s)\n", errstr);
	}
}

struct sslbuffer_t *SSLBufferCreate(SSL_CTX *ctx, struct event_base *base)
{
	struct sslbuffer_t *sslbuffer = NULL;
	SSL *ssl = NULL;
	struct buffer_t *write_buffer_1 = NULL;
	struct buffer_t *write_buffer_2 = NULL;
	
	sslbuffer = (struct sslbuffer_t *) malloc(sizeof(struct sslbuffer_t));
	if (sslbuffer == NULL)
		goto Error;
	memset(sslbuffer, 0, sizeof(*sslbuffer));
	sslbuffer->ctx = ctx;

	ssl = SSL_new(ctx);
	if (ssl == NULL)
		goto Error;
	SSL_set_cipher_list(ssl, CIPHER_LIST);
	sslbuffer->ssl = ssl;
	
	sslbuffer->base = base;

	write_buffer_1 = BufferCreate(256);
	if (write_buffer_1 == NULL)
		goto Error;
	sslbuffer->write_buffer_1 = write_buffer_1;

	write_buffer_2 = BufferCreate(256);
	if (write_buffer_2 == NULL)
		goto Error;
	sslbuffer->write_buffer_2 = write_buffer_2;
	
	sslbuffer->fl_connecting = 0;
	sslbuffer->fl_reading = 0;
	sslbuffer->fl_writing = 0;
	sslbuffer->fl_want_read = 0;
	sslbuffer->fl_want_write = 0;

	return sslbuffer;

Error:
	if (write_buffer_2 != NULL)
		BufferDelete(write_buffer_2);
	if (write_buffer_1 != NULL)
		BufferDelete(write_buffer_1);
	if (ssl != NULL)
		SSL_free(ssl);
	free(sslbuffer);
	return NULL;
}

void SSLBufferDelete(struct sslbuffer_t *sslbuffer)
{
	if (sslbuffer->ev_write != NULL)
		event_free(sslbuffer->ev_write);
	if (sslbuffer->ev_read != NULL)
		event_free(sslbuffer->ev_read);
	if (sslbuffer->write_buffer_1 != NULL)
		BufferDelete(sslbuffer->write_buffer_1);
	if (sslbuffer->write_buffer_2 != NULL)
		BufferDelete(sslbuffer->write_buffer_2);
	if (sslbuffer->ssl != NULL)
		SSL_free(sslbuffer->ssl);
	free(sslbuffer);
}

int SSLBufferConnect(struct sslbuffer_t *sslbuffer, const char *host,
	const char *port)
{
	int res;
	int fd;
	struct event *ev_write = NULL;
	struct event *ev_read = NULL;
	BIO *bio = NULL;
	unsigned long error;

	bio = BIO_new(BIO_s_connect( ));
	if (bio == NULL)
		return 0;

	BIO_set_conn_hostname(bio, host);
	BIO_set_conn_port(bio, port);
	BIO_set_nbio(bio, 1);

	SSL_set_bio(sslbuffer->ssl, bio, bio);

	res = SSL_connect(sslbuffer->ssl);
	if (res <= 0)
	{
		error = SSL_get_error(sslbuffer->ssl, res);
		sslbuffer->fl_connecting = 1;
		if ( (error != SSL_ERROR_WANT_CONNECT) &&
		     (error != SSL_ERROR_WANT_READ) &&
		     (error != SSL_ERROR_WANT_WRITE) )
		{
			printf("%s:%d: unknown error %lu\n", __FILE__, __LINE__, error);
			print_errors();
			goto Error;
		}
	}

	fd = BIO_get_fd(bio, NULL);

	ev_read = event_new(sslbuffer->base, fd, EV_READ|EV_PERSIST, SSLBuffer_func, sslbuffer);
	if (ev_read == NULL)
		goto Error;
	res = event_add(ev_read, NULL);
	if (res != 0)
		goto Error;
	sslbuffer->ev_read = ev_read;

	ev_write = event_new(sslbuffer->base, fd, EV_WRITE|EV_PERSIST, SSLBuffer_func, sslbuffer);
	if (ev_write == NULL)
		goto Error;

    res = event_add(ev_write, NULL);
    if (res != 0)
        goto Error;
	sslbuffer->ev_write = ev_write;

	return 1;

Error:
	if (ev_write != NULL)
		event_free(ev_write);
	if (ev_read != NULL)
		event_free(ev_read);
	return 0;
}

void SSLBuffer_func(evutil_socket_t fd, short event, void *arg)
{
	struct sslbuffer_t *sslbuffer = (struct sslbuffer_t *) arg;
	int res;
	unsigned long error;

	if (sslbuffer->fl_connecting)
	{
		res = SSL_connect(sslbuffer->ssl);
		if (res <= 0)
		{
			error = SSL_get_error(sslbuffer->ssl, res);
			sslbuffer->fl_want_read = 0;
			sslbuffer->fl_want_write = 0;
			if ( (error != SSL_ERROR_WANT_CONNECT) &&
				 (error != SSL_ERROR_WANT_READ) && (error != SSL_ERROR_WANT_WRITE) )
			{
				printf("%s:%d: unknown error %lu\n", __FILE__, __LINE__, error);
				print_errors();
			}
		}
		else
		{
			(sslbuffer->eventcb)(sslbuffer, EVT_CONNECTED, sslbuffer->cb_ctx);
			sslbuffer->fl_connecting = 0;
			sslbuffer->fl_want_read = 0;
			sslbuffer->fl_want_write = 0;
		}
		return;
	}

    if (sslbuffer->fl_writing)
    {
        if ( (sslbuffer->fl_want_read && (event & EV_READ)) ||
             (sslbuffer->fl_want_write && (event & EV_WRITE)))
        {
            SSLBufferTryWrite(sslbuffer);
        }
        return;
    }

    if (sslbuffer->fl_reading)
    {
        if ( (sslbuffer->fl_want_read && (event & EV_READ)) ||
             (sslbuffer->fl_want_write && (event & EV_WRITE)))
        {
            SSLBufferTryRead(sslbuffer);
        }
        return;
    }

	if (event & EV_WRITE)
	{
		SSLBufferTryWrite(sslbuffer);
	}

	if (event & EV_READ)
	{
		SSLBufferTryRead(sslbuffer);
	}
}

void SSLBufferWrite(struct sslbuffer_t *sslbuffer, uint8_t *data, size_t size)
{
	int res;

	BufferPush(sslbuffer->write_buffer_1, data, size);
	res = event_add(sslbuffer->ev_write, NULL);
}

int SSLBufferSetCB(
	struct sslbuffer_t *sslbuffer,
	SSLBuffer_read_cb readcb,
	SSLBuffer_event_cb eventcb,
	void *ctx)
{
	sslbuffer->readcb = readcb;
	sslbuffer->eventcb = eventcb;
	sslbuffer->cb_ctx = ctx;
	return 1;
}

void SSLBufferTryWrite(struct sslbuffer_t *sslbuffer)
{
	int res;
	unsigned long error;

	if (!sslbuffer->fl_writing)
	{
		if (BufferSize(sslbuffer->write_buffer_1) > 0)
			BufferCopy(sslbuffer->write_buffer_2, sslbuffer->write_buffer_1);
	}
	if (BufferSize(sslbuffer->write_buffer_2) > 0)
	{
		res = SSL_write(
			sslbuffer->ssl,
			BufferStart(sslbuffer->write_buffer_2),
			BufferSize(sslbuffer->write_buffer_2));
		if (res <= 0)
		{
			error = SSL_get_error(sslbuffer->ssl, res);
			sslbuffer->fl_writing = 1;
			if (error == SSL_ERROR_WANT_READ)
				sslbuffer->fl_want_read = 1;
			else if (error == SSL_ERROR_WANT_WRITE)
				sslbuffer->fl_want_write = 1;
			else
			{
				printf("%s:%d: unknown error %lu\n", __FILE__, __LINE__, error);
				print_errors();
				event_base_loopbreak(sslbuffer->base);
			}
			return;
		}

		BufferRemove(sslbuffer->write_buffer_2, (size_t) res);
		sslbuffer->fl_writing = 0;
		sslbuffer->fl_want_write = 0;
		sslbuffer->fl_want_read = 0;
	}

	if ( (BufferSize(sslbuffer->write_buffer_1) == 0) &&
		 (BufferSize(sslbuffer->write_buffer_2) == 0))
	{
		event_del(sslbuffer->ev_write);
	}
}

void SSLBufferTryRead(struct sslbuffer_t *sslbuffer)
{
	int res;
	static uint8_t buffer[256];
	unsigned long error;
	int errno_keep;

	do
	{
		res = SSL_read(sslbuffer->ssl, buffer, sizeof(buffer));
		errno_keep = errno;
		if (res <= 0)
		{
			error = SSL_get_error(sslbuffer->ssl, res);
			sslbuffer->fl_reading = 1;
			if (error == SSL_ERROR_WANT_READ)
				sslbuffer->fl_want_read = 1;
			else if (error == SSL_ERROR_WANT_WRITE)
				sslbuffer->fl_want_write = 1;
			else if (error == SSL_ERROR_ZERO_RETURN)
			{
				printf("%s:%d: SSL_read got SSL_ERROR_ZERO_RETURN\n", __FILE__,
					__LINE__);
				event_base_loopbreak(sslbuffer->base);
			}
			else if (error == SSL_ERROR_SYSCALL)
			{
				printf("%s:%d: SSL_read got SSL_ERROR_SYSCALL (%s)\n", __FILE__,
					 __LINE__, strerror(errno_keep));
				event_base_loopbreak(sslbuffer->base);
			}
			else
			{
				printf("%s:%d: other error %lu\n", __FILE__, __LINE__, error);
				print_errors();
				event_base_loopbreak(sslbuffer->base);
			}
			return;
		}
		(sslbuffer->readcb)(sslbuffer, buffer, res, sslbuffer->cb_ctx);
		sslbuffer->fl_reading = 0;
		sslbuffer->fl_want_write = 0;
		sslbuffer->fl_want_read = 0;
	} while (SSL_pending(sslbuffer->ssl));
}

