#ifndef IOKIT_H
#define IOKIT_H

#include "IOKitLib.h"

typedef char io_name_t[128];
typedef io_object_t io_registry_entry_t;
typedef io_object_t io_iterator_t;

kern_return_t IORegistryEntryGetName(io_registry_entry_t entry, io_name_t name);

io_object_t IOIteratorNext(io_iterator_t it);
boolean_t IOIteratorIsValid(io_iterator_t it);

#endif /* IOKIT_H */
