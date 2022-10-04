
#include <stdint.h>
#include <string.h>
#ifdef WIN32
#include <sys/time.h>
#else
#include <time.h>
#endif
#include "crc.h"

namespace vjoy_event_net {

enum NetModeT: uint8_t {
    NetModeT_INPUT_EVENT = 0,
    NetModeT_MAX
};

typedef struct HeaderT_struct {
    uint8_t mode;
    uint64_t ts;
    uint32_t crc;
    uint32_t length;
    uint32_t length_inverse;
} HeaderT;

typedef struct HeaderNetT_struct {
    uint8_t mode[1];
    uint8_t ts[8];
    uint8_t crc[4];
    uint8_t length[4];
    uint8_t length_inverse[4];
} HeaderNetT;

typedef struct InputEventT_struct {
    uint64_t tv_sec;
    uint64_t tv_usec;

    uint16_t type;
    uint16_t code;
    int32_t value;
} InputEventT;

typedef struct InputEventNetT_struct {
    uint8_t tv_sec[8];
    uint8_t tv_usec[8];

    uint8_t type[2];
    uint8_t code[2];
    uint8_t value[4];
} InputEventNetT;

inline void EventDump(InputEventT &input, InputEventNetT &output){
    int index;
    for(index = 0; index < sizeof(input.tv_sec); index++){
        output.tv_sec[index] = (uint8_t)(input.tv_sec >> (index * 8));
    }
    for(index = 0; index < sizeof(input.tv_usec); index++){
        output.tv_usec[index] = (uint8_t)(input.tv_usec >> (index * 8));
    }
    for(index = 0; index < sizeof(input.type); index++){
        output.type[index] = (uint8_t)(input.type >> (index * 8));
    }
    for(index = 0; index < sizeof(input.code); index++){
        output.code[index] = (uint8_t)(input.code >> (index * 8));
    }
    for(index = 0; index < sizeof(input.value); index++){
        output.value[index] = (uint8_t)(input.value >> (index * 8));
    }
}

inline void EventLoad(InputEventT &output, InputEventNetT &input){
    int index;
    output.tv_sec = 0;
    for(index = 0; index < sizeof(input.tv_sec); index++){
        output.tv_sec |= ((uint64_t)input.tv_sec[index]) << (index * 8);
    }
    output.tv_usec = 0;
    for(index = 0; index < sizeof(input.tv_usec); index++){
        output.tv_usec |= ((uint64_t)input.tv_usec[index]) << (index * 8);
    }
    output.type = 0;
    for(index = 0; index < sizeof(input.type); index++){
        output.type |= ((uint16_t)input.type[index]) << (index * 8);
    }
    output.code = 0;
    for(index = 0; index < sizeof(input.code); index++){
        output.code |= ((uint16_t)input.code[index]) << (index * 8);
    }
    output.value = 0;
    for(index = 0; index < sizeof(input.value); index++){
        output.value |= (int32_t)(((uint32_t)input.value[index]) << (index * 8));
    }
}

inline void HeaderDump(HeaderT &input, HeaderNetT &output){
    int index;
    for(index = 0; index < sizeof(input.mode); index++){
        output.mode[index] = (uint8_t)(input.mode >> (index * 8));
    }
    for(index = 0; index < sizeof(input.ts); index++){
        output.ts[index] = (uint8_t)(input.ts >> (index * 8));
    }
    for(index = 0; index < sizeof(input.crc); index++){
        output.crc[index] = (uint8_t)(input.crc >> (index * 8));
    }
    for(index = 0; index < sizeof(input.length); index++){
        output.length[index] = (uint8_t)(input.length >> (index * 8));
    }
    for(index = 0; index < sizeof(input.length_inverse); index++){
        output.length_inverse[index] = (uint8_t)(input.length_inverse >> (index * 8));
    }
}

inline void HeaderLoad(HeaderT &output, HeaderNetT &input){
    int index;
    output.mode = 0;
    for(index = 0; index < sizeof(input.mode); index++){
        output.mode |= ((uint8_t)input.mode[index]) << (index * 8);
    }
    output.ts = 0;
    for(index = 0; index < sizeof(input.ts); index++){
        output.ts |= ((uint8_t)input.ts[index]) << (index * 8);
    }
    output.ts = 0;
    for(index = 0; index < sizeof(input.ts); index++){
        output.ts |= ((uint8_t)input.ts[index]) << (index * 8);
    }
    output.crc = 0;
    for(index = 0; index < sizeof(input.crc); index++){
        output.crc |= ((uint8_t)input.crc[index]) << (index * 8);
    }
    output.length = 0;
    for(index = 0; index < sizeof(input.length); index++){
        output.length |= ((uint8_t)input.length[index]) << (index * 8);
    }
    output.length_inverse = 0;
    for(index = 0; index < sizeof(input.length_inverse); index++){
        output.length_inverse |= ((uint8_t)input.length_inverse[index]) << (index * 8);
    }
}

inline int PackData(void * buf, size_t buf_len, NetModeT mode, void * data, uint32_t data_len){
    /* Check space to unpack */
    if (buf_len < (data_len + sizeof(HeaderNetT))){
        return 0;
    }

    HeaderT header;
    struct timespec tv;
    clock_gettime(CLOCK_REALTIME, &tv);
    header.ts = tv.tv_sec*1000000000ull + tv.tv_nsec;
    header.mode = mode;
    header.length = data_len;
    header.length_inverse = ~header.length;
    header.crc = crc32buf(static_cast<char *>(data), data_len);
    HeaderDump(header, *static_cast<HeaderNetT *>(buf));
    /* Allow inline filling, so only copy if address is different */
    if (data != &(static_cast<char *>(buf)[sizeof(HeaderNetT)]))
    {
        memcpy(&(static_cast<char *>(buf)[sizeof(HeaderNetT)]), data, data_len);
    }

    return data_len + sizeof(HeaderNetT);
}

inline int CheckHeader(void * buf, size_t buf_len){
    HeaderT header;
    /* Check buffer is large enough to extract header */
    if (buf_len < sizeof(HeaderNetT)){
        return -1;
    }
    HeaderLoad(header, *static_cast<HeaderNetT *>(buf));
    /* Check data validitiy of header, without needing data to calc CRC */
    if ((header.mode >= NetModeT_MAX) || (header.length != ~ header.length_inverse)){
        return 1;
    }

    return 0;
}

// Return bytes read into the data buffer
// -1 means an input buffer is to small for the header
// -2 means data problems
inline int UnpackData(void * buf, size_t buf_len, HeaderT &header, void * data, uint32_t data_len){
    /* Check buffer is large enough to extract header */
    if (buf_len < sizeof(HeaderNetT)){
        return -1;
    }
    HeaderLoad(header, *static_cast<HeaderNetT *>(buf));
    /* Check data validitiy of header, without needing data to calc CRC */
    if ((header.mode >= NetModeT_MAX) || (header.length != ~ header.length_inverse)){
        return -2;
    }
    /* Check that there is enoguth data to extract everything */
    if (data_len < (header.length)){
        return -1;
    }
    /* Check that there is enoguth data to extract everything */
    if (buf_len < (header.length + sizeof(HeaderNetT))){
        return -3;
    }
    /* Allow inline unpacking, only copy if data location is differnt */
    if (data != &(static_cast<char *>(buf)[sizeof(HeaderNetT)]))
    {
        memcpy(data, &(static_cast<char *>(buf)[sizeof(HeaderNetT)]), header.length);
    }
    /* Check the CRC is okay */
    uint32_t crc = crc32buf(static_cast<char *>(data), header.length);
    if (crc != header.crc){
        return -2;
    }
    return header.length;
}

}
