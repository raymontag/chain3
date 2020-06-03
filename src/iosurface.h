#ifndef IOSURFACE_H
#define IOSURFACE_H

#include <mach/mach.h>
#include "iokit.h"

#define IOSURFACE_ROOT ("IOSurfaceRoot")

// IOSurfaceRootClient methods
#define SURFACE_CREATE 0
#define SURFACE_RELEASE 1
#define SURFACE_SET_VALUE 9
#define SURFACE_GET_VALUE 10
#define SURFACE_REMOVE_VALUE 11

#define SURFACE_CREATE_OUTPUT_SIZE 0xbc8
#define SURFACE_RELEASE_INPUT_COUNT 1
#define SURFACE_SET_VALUE_OUTPUT_SIZE 4
#define SURFACE_REMOVE_VALUE_OUTPUT_SIZE 4

typedef union
{
    char _padding[SURFACE_CREATE_OUTPUT_SIZE];
    struct
    {
	mach_vm_address_t addr1;
	mach_vm_address_t addr2;
	uint32_t id;
    } data;
} create_surface_output_t;

int open_connection_to_iosurface_client(io_connect_t *connection);
int io_surface_create(io_connect_t *connection, uint32_t *surface_id);
int io_surface_release(io_connect_t *connection, uint64_t surface_id);
int io_surface_set_value(io_connect_t *connection, uint32_t *surface_id,
			 char **input_buffer);
int io_surface_get_value(io_connect_t *connection, uint32_t *surface_id,
			 uint32_t *output_struct, size_t *output_size);
int io_surface_remove_value_all(io_connect_t *connection, uint32_t surface_id);

#endif // IOSURFACE_H
