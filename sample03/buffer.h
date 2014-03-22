#ifndef _buffer_h_
#define _buffer_h_

#include <stdlib.h>
#include <stdint.h>

struct buffer_t {
	uint8_t *buffer;
	size_t capacity;
	uint8_t *data;
	size_t size;
};

struct buffer_t *BufferCreate(size_t capacity);
void BufferDelete(struct buffer_t *buffer);

void BufferPush(struct buffer_t *buffer, uint8_t *data, size_t size);
uint8_t *BufferStart(struct buffer_t *buffer);
size_t BufferSize(struct buffer_t *buffer);
void BufferPeek(struct buffer_t *buffer, uint8_t *data, size_t size);
void BufferRemove(struct buffer_t *buffer, size_t size);
void BufferCopy(struct buffer_t *buffer, struct buffer_t *src);

#endif /* !_buffer_h_ */

