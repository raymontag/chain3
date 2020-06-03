#ifndef APPLEVXD393_H
#define APPLEVXD393_H

#include "iokit.h"

#define IOKIT_ALL_SERVICES          ("IOService")
#define IOKIT_VULNERABLE_SERVICE  ("AppleVXD393")

// AppleVXD393UserClient methods
#define CREATE_DECODER 0
#define DESTROY_DECODER 1

#define CREATE_DECODER_INPUT_SIZE 0xf0
#define CREATE_DECODER_OUTPUT_SIZE 0x40

#define DESTROY_DECODER_INPUT_SIZE 0x4
#define DESTROY_DECODER_OUTPUT_SIZE 0x84

int open_connection_to_applevxd393(io_connect_t *userclient_connection);
int create_decoder(io_connect_t *userclient_connection, uint32_t *surface_id);
int destroy_decoder(io_connect_t *userclient_connection);

#endif // APPLEVXD393_H
