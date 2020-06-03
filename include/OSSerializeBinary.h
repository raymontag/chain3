#ifndef _OS_OSSERIALIZEBINARY_H
#define _OS_OSSERIALIZEBINARY_H

enum 
{
  kOSSerializeDictionary   = 0x01000000U,
  kOSSerializeArray        = 0x02000000U,
  kOSSerializeSet          = 0x03000000U,
  kOSSerializeNumber       = 0x04000000U,
  kOSSerializeSymbol       = 0x08000000U,
  kOSSerializeString       = 0x09000000U,
  kOSSerializeData         = 0x0a000000U,
  kOSSerializeBoolean      = 0x0b000000U,
  kOSSerializeObject       = 0x0c000000U,
  kOSSerializeTypeMask     = 0x7F000000U,
  kOSSerializeDataMask     = 0x00FFFFFFU,
  kOSSerializeEndCollection = 0x80000000U,
};

#define kOSSerializeBinarySignature 0x000000d3U // "\323\0\0"


#endif /* _OS_OSSERIALIZEBINARY_H */
