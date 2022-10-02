
#include <stdint.h>

typedef struct InputEvent_struct {
    uint64_t tv_sec;
    uint64_t tv_usec;

    uint16_t type;
    uint16_t code;
    int32_t value;
} InputEvent;

typedef struct InputEventNet_struct {
    uint8_t tv_sec[8];
    uint8_t tv_usec[8];

    uint8_t type[2];
    uint8_t code[2];
    uint8_t value[4];
} InputEventNet;

inline void EventDump(InputEvent &input, InputEventNet &output){
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

inline void EventLoad(InputEvent &output, InputEventNet &input){
    int index;
    output.tv_sec = 0;
    for(index = 0; index < sizeof(input.tv_sec); index++){
        output.tv_sec |= ((uint64_t)input.tv_sec) << (index * 8);
    }
    output.tv_usec = 0;
    for(index = 0; index < sizeof(input.tv_usec); index++){
        output.tv_usec |= ((uint64_t)input.tv_usec) << (index * 8);
    }
    output.type = 0;
    for(index = 0; index < sizeof(input.type); index++){
        output.type |= ((uint16_t)input.type) << (index * 8);
    }
    output.code = 0;
    for(index = 0; index < sizeof(input.code); index++){
        output.code |= ((uint16_t)input.code) << (index * 8);
    }
    output.value = 0;
    for(index = 0; index < sizeof(input.value); index++){
        output.value |= (int32_t)(((uint32_t)input.value) << (index * 8));
    }
}
