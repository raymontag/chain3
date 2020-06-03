#include "helper.h"
#include "iosurface.h"
#include "iokit.h"

int open_connection_to_iosurface_client(io_connect_t *connection)
{
    io_service_t service;
    mach_port_t master_port;
    kern_return_t ret;

    *connection = 0;
    master_port = 0;

    if ((ret = host_get_io_master(mach_host_self(), &master_port)) != KERN_SUCCESS)
    {
        ERROR_LOG("Failed Getting Master Port");
	return 1;
    }

    service = IOServiceGetMatchingService(master_port,
					  IOServiceMatching(IOSURFACE_ROOT));
    if (!MACH_PORT_VALID(service))
    {
        ERROR_LOG2("Failed Getting IOSurfaceRoot");
	return 1;
    }

    if ((ret = IOServiceOpen(service, mach_task_self(), 0, connection)) != KERN_SUCCESS ||
	!MACH_PORT_VALID(*connection))
    {
	ERROR_LOG("Error Opening Service %s", IOSURFACE_ROOT);
	return 1;
    }

    DEBUG_LOG("Successfully Opened Connection To %s", IOSURFACE_ROOT);

    return 0;
}

int io_surface_create(io_connect_t *connection, uint32_t *surface_id)
{
    char *input_struct;
    create_surface_output_t output_surface;
    size_t output_size;
    kern_return_t ret;

    asprintf(&input_struct,
	     "%s%s%s%s",
	     "<dict>",
	     "<key>IOSurfaceAllocSize</key>",
	     "<integer>32</integer>",
	     "</dict>");
    output_size = sizeof(output_surface);
    ret = IOConnectCallStructMethod(*connection, SURFACE_CREATE,
				    input_struct, strlen(input_struct) + 1,
				    &output_surface, &output_size);

    if (ret != KERN_SUCCESS)
    {
	ERROR_LOG("Create Surface Failed: %x", ret);
	return 1;
    }
    else
    {
	*surface_id = output_surface.data.id;
	DEBUG_LOG("Successfully Created Surface With ID: %d", *surface_id);
    }

    return 0;

}

int io_surface_release(io_connect_t *connection, uint64_t surface_id)
{
    kern_return_t ret;

    ret = IOConnectCallScalarMethod(*connection, SURFACE_RELEASE,
				    &surface_id, SURFACE_RELEASE_INPUT_COUNT,
				    NULL, NULL);
    if (ret != KERN_SUCCESS)
    {
	ERROR_LOG("Release Surface %lld Failed: %x", surface_id, ret);
	return 1;
    }
    else
    {
	DEBUG_LOG("Successfully Released Surface %lld", surface_id);
    }

    return 0;
}

int io_surface_set_value(io_connect_t *connection, uint32_t *surface_id,
			 char **input_buffer)
{
    char *input_struct;
    size_t input_size, input_buffer_size;
    size_t set_value_output_size;
    uint32_t set_value_output;
    kern_return_t ret;

    input_buffer_size = strlen(*input_buffer);
    input_size = sizeof(uint64_t) + input_buffer_size + 1;
    input_struct = calloc(input_size, sizeof(char));

    *(uint64_t *)input_struct = *surface_id;
    memcpy(input_struct + sizeof(uint64_t), *input_buffer, input_buffer_size);

    set_value_output_size = SURFACE_SET_VALUE_OUTPUT_SIZE;
    ret = IOConnectCallStructMethod(*connection, SURFACE_SET_VALUE,
				    input_struct, input_size,
    				    &set_value_output, &set_value_output_size);
    if (ret != KERN_SUCCESS)
    {
	ERROR_LOG("Set Value On Surface %u Failed: %x", *surface_id, ret);
	return 1;
    }
    else
    {
	DEBUG_LOG("Successfully Set Value On Surface %u", *surface_id);
    }

    free(input_struct);
    return 0;
}

int io_surface_get_value(io_connect_t *connection, uint32_t *surface_id,
			 uint32_t *output_struct, size_t *output_size)
{
    char *input_struct;
    size_t input_size, input_buffer_size;
    kern_return_t ret;

    input_size = sizeof(uint64_t) * 2 ;
    input_struct = calloc(input_size, sizeof(char));

    *(uint64_t *)input_struct = *surface_id;
    *((uint64_t *)input_struct + sizeof(uint64_t)) = 0x0000007961727073;

    bzero(output_struct, *output_size);

    ret = IOConnectCallStructMethod(*connection, SURFACE_GET_VALUE,
				    input_struct, input_size,
    				    output_struct, output_size);
    if (ret != KERN_SUCCESS)
    {
	ERROR_LOG("Get Value On Surface %u Failed: %x", *surface_id, ret);
	return 1;
    }
    else
    {
	DEBUG_LOG("Successfully Get Value On Surface %u", *surface_id);
    }

    free(input_struct);
    return 0;

}

int io_surface_remove_value_all(io_connect_t *connection, uint32_t surface_id)
{
    char *input_struct;
    size_t input_size, output_size;
    uint32_t output;
    kern_return_t ret;

    input_size = sizeof(uint64_t) * 2 ;
    input_struct = calloc(input_size, sizeof(char));

    *(uint64_t *)input_struct = surface_id;

    output_size = SURFACE_REMOVE_VALUE_OUTPUT_SIZE;
    ret = IOConnectCallStructMethod(*connection, SURFACE_REMOVE_VALUE,
				    input_struct, input_size,
    				    &output, &output_size);
    if (ret != KERN_SUCCESS)
    {
	ERROR_LOG("Remove All Values On Surface %u Failed: %x", surface_id, ret);
	return 1;
    }
    else
    {
	DEBUG_LOG("Successfully Removed Values On Surface %u", surface_id);
    }

    free(input_struct);
    return 0;
}
