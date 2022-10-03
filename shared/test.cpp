
#include "vjoy_event_net.hpp"
#include <iostream>
#include <assert.h>
#include <string.h>

using namespace vjoy_event_net;

constexpr int BUF_SIZE = 4096;

uint8_t buf[BUF_SIZE];

int main()
{
    InputEventT ie1;
    ie1.code = 5;
    ie1.tv_sec = 99402543;
    ie1.tv_usec = 103021543;
    ie1.type = 435;
    ie1.value = -442246474;

    EventDump(ie1, *((InputEventNetT *)(void *)&buf[0]));

    InputEventT ie2;

    EventLoad(ie2, *((InputEventNetT *)(void *)&buf[0]));

    assert(0 == memcmp(&ie1, &ie2, sizeof(ie1)));

    InputEventT ie3;

    EventDump(ie1, *((InputEventNetT *)(void *)&buf[sizeof(HeaderNetT)]));
    assert(0 == PackData(buf, BUF_SIZE, NetModeT_INPUT_EVENT, static_cast<void *>(&buf[sizeof(HeaderNetT)]), sizeof(InputEventNetT)));
    assert(0 == CheckHeader(buf, BUF_SIZE));
    HeaderT header;
    assert(sizeof(InputEventNetT) == UnpackData(buf, BUF_SIZE, header, static_cast<void *>(&buf[sizeof(HeaderNetT)]), sizeof(InputEventNetT)));
    assert(header.mode == NetModeT_INPUT_EVENT);
    EventLoad(ie3, *((InputEventNetT *)(void *)&buf[sizeof(HeaderNetT)]));
    assert(0 == memcmp(&ie1, &ie3, sizeof(ie1)));
}
