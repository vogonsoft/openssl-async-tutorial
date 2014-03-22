#include "buffer.h"
#include <string.h>

struct buffer_t *BufferCreate(size_t capacity)
{
	struct buffer_t *buffer;
	
	buffer = (struct buffer_t *) malloc(sizeof(struct buffer_t));
	if (buffer == NULL)
		goto Error;
	memset(buffer, 0, sizeof(*buffer));
	buffer->buffer = (uint8_t *) malloc(capacity);
	if (buffer->buffer == NULL)
		goto Error;
	buffer->capacity = capacity;
	buffer->data = buffer->buffer;
	buffer->size = 0;

	return buffer;

Error:
	if (buffer != NULL)
	{
		if (buffer->buffer != NULL)
			free(buffer->buffer);
		free(buffer);
	}
	return NULL;
}

void BufferDelete(struct buffer_t *buffer)
{
	if (buffer != NULL)
	{
		free(buffer->buffer);
		free(buffer);
	}
}

void BufferPush(struct buffer_t *buffer, uint8_t *data, size_t size)
{
	/* If the remaining free space is not large enough, reduce size. */
	if (size + buffer->size > buffer->capacity)
		size = buffer->capacity - buffer->size;
	
	/* If the free space at the end is not large enough, move the data
	   to the beginning of the buffer. */
	if (size > buffer->capacity - buffer->size - (buffer->data - buffer->buffer))
	{
		memmove(buffer->buffer, buffer->data, buffer->size);
		buffer->data = buffer->buffer;
	}
	memcpy(buffer->data + buffer->size, data, size);
	buffer->size += size;
}

size_t BufferSize(struct buffer_t *buffer)
{
	return buffer->size;
}

void BufferPeek(struct buffer_t *buffer, uint8_t *data, size_t size)
{
	if (buffer->size < size)
		size = buffer->size;
	memcpy(data, buffer->data, size);
}

void BufferRemove(struct buffer_t *buffer, size_t size)
{
	if (buffer->size < size)
		size = buffer->size;
	buffer->data += size;
	buffer->size -= size;
}

