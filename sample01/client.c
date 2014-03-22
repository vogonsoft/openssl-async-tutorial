#include <stdio.h>
#include <stdlib.h>

#include <event2/event.h>

int
main(int argc, char **argv)
{
	char *host;
	int port;
	struct event_base *base;
	struct timeval two_sec;

	two_sec.tv_sec = 2;
	two_sec.tv_usec = 0;

	base = event_base_new();
	if (!base)
	{
		fprintf(stderr, "Error creating event_base!\n");
		exit(-1);
	}
	
	printf("Starting event loop\n");
	
	/* Schedule an exit in the future */
	event_base_loopexit(base, &two_sec);
	
	/* Run the event loop */
	event_base_dispatch(base);
	
	/* At the end */
	event_base_free(base);

	return 0;
}

