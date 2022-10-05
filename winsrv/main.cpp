
#include "vjoywrapper.h"
#include "winsockwrapper.hpp"
#include "vjoy_event_net.hpp"
#include <iostream>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h> 
#include <stdInt.h>
//#include <sys/socket.h>
//#include <netinet/in.h>

constexpr int RX_BUF_LENGTH = (1024 * 1024);

namespace vjn = vjoy_event_net;

int key_to_btn[][2] = {
    { 28, 1 },
    { 240, 2 },
    { 304, 3 },
    { 305, 4 },
    { 307, 5 },
    { 308, 6 },
    { 310, 7 },
    { 311, 8 },
    { 314, 9 },
    { 315, 10 },
    { 316, 11 },
    { 317, 12 },
    { 318, 13 },
    { 740, 14 },
    { 741, 15 },
    { 742, 16 },
    { 743, 17 }
};

constexpr int key_to_btn_len = sizeof(key_to_btn)/(sizeof(int)*2);

constexpr int InputEvent_CodeKey = 1;
constexpr int InputEvent_Absolute = 3;

int main()
{
    SockSimple test{};
    int rx_length = 0;
    int work_len = 0;
    char * work_buf;
    char buffer_data[RX_BUF_LENGTH];
    char * buf_start = buffer_data;
    int buf_len = RX_BUF_LENGTH;

    std::cout << GetvJoyVersion() << std::endl;
    std::cout << AcquireVJD(1) << std::endl;
    // This function does not seem to work, or the descriptions does not do what I expect from the header file
    std::cout << ResetVJD(1) << std::endl;
    // This function seems to work
    std::cout << ResetButtons(1) << std::endl;
    // I never set and Povs, so who knows
    std::cout << ResetPovs(1) << std::endl;

    SetAxis(INT16_MAX/2, 1, HID_USAGE_X);
    SetAxis(INT16_MAX/2, 1, HID_USAGE_Y);
    SetAxis(0, 1, HID_USAGE_Z);
    SetAxis(INT16_MAX/2, 1, HID_USAGE_RX);
    SetAxis(INT16_MAX/2, 1, HID_USAGE_RY);
    SetAxis(0, 1, HID_USAGE_RZ);
    SetAxis(0, 1, HID_USAGE_SL0);
    SetAxis(0, 1, HID_USAGE_SL1);

    test.WaitForConnection();
    do
    {
        rx_length = test.ReceiveData(buf_start, buf_len);
        work_len = rx_length;
        work_buf = buffer_data;

        // Scan if there are errors till no data remains
        int result = vjn::CheckHeader(work_buf, work_len);
        while ((work_len > 0) && (0 != result))
        {
            work_buf++;
            work_len--;
            result = vjn::CheckHeader(work_buf, work_len);
        }
        if (result != 0){
             std::cout << "No valid header found" << std::endl;
        }
        // Extract the data if there is enough data
        if (0 == result){
            vjn::HeaderT header;
            int extracted = vjn::UnpackData(work_buf, work_len, header, &work_buf[sizeof(vjn::HeaderNetT)], work_len-sizeof(vjn::HeaderNetT));
            if (extracted == -3){
                // Not all data avaliable yet
                std::cout << "Waiting for more data" << std::endl;
                memcpy(buffer_data, work_buf, work_len);
                buf_start = &buffer_data[work_len];
                buf_len = RX_BUF_LENGTH-work_len;
            }
            else if (extracted < 0){
                // Failure, try to recover
                std::cout << "Error, header corrupt or data corrupt" << std::endl;
                buf_start = buffer_data;
                buf_len = RX_BUF_LENGTH;
            }
            else{
                // Reset buffer
                buf_start = buffer_data;
                buf_len = RX_BUF_LENGTH;
                // std::cout << "HeaderT:" << std::endl;
                // std::cout << "  mode: " << header.mode << std::endl;
                // std::cout << "  ts: " << header.ts << std::endl;
                // std::cout << "  length: " << header.length << std::endl;
                // std::cout << "  length_inverse: " << header.length_inverse << std::endl;
                // std::cout << "  crc: " << header.crc << std::endl;
                if (header.mode == vjn::NetModeT_INPUT_EVENT){
                    int total_events = extracted / sizeof(vjn::InputEventNetT);
                    std::cout << "Decoding " << total_events << " Input Events:" << std::endl;
                    // Loop through all avaliable events
                    char * ev_buf_ptr = &work_buf[sizeof(vjn::HeaderNetT)];
                    for(int ev_index = 0; ev_index < total_events; ev_index++){
                        vjn::InputEventT input_event;
                        vjn::EventLoad(input_event, *(static_cast<vjn::InputEventNetT *>(static_cast<void *>(ev_buf_ptr))));
                        if (input_event.tv_sec){
                            std::cout << "  Input Event:" << std::endl;
                            std::cout << "    tv_sec: " << input_event.tv_sec << std::endl;
                            std::cout << "    tv_usec: " << input_event.tv_usec << std::endl;
                            std::cout << "    type: " << input_event.type << std::endl;
                            std::cout << "    code: " << input_event.code << std::endl;
                            std::cout << "    value: " << input_event.value << std::endl;
                        }
                        ev_buf_ptr = &ev_buf_ptr[sizeof(vjn::InputEventNetT)];
                        //Check for buttons
                        if (input_event.type == InputEvent_CodeKey){
                            for (int index = 0; index < key_to_btn_len; index++){
                                if (input_event.code == key_to_btn[index][0]){
                                    SetBtn(input_event.value, 1, key_to_btn[index][1]);
                                    break;
                                }
                            }
                        }
                        else if (input_event.type == InputEvent_Absolute){
                            if (input_event.code == 0)
                            {
                                SetAxis((input_event.value + 32768) * 32767/65535, 1, HID_USAGE_X);
                            }
                            else if (input_event.code == 1)
                            {
                                SetAxis((input_event.value + 32768) * 32767/65535, 1, HID_USAGE_Y);
                            }
                            else if (input_event.code == 2)
                            {
                                SetAxis(input_event.value * 32767/1023, 1, HID_USAGE_SL0);
                            }
                            else if (input_event.code == 3)
                            {
                                SetAxis((input_event.value + 32768) * 32767/65535, 1, HID_USAGE_RX);
                            }
                            else if (input_event.code == 4)
                            {
                                SetAxis((input_event.value + 32768) * 32767/65535, 1, HID_USAGE_RY);
                            }
                            else if (input_event.code == 5)
                            {
                                SetAxis(input_event.value * 32767/1023, 1, HID_USAGE_SL1);
                            }
                            else if (input_event.code == 40)
                            {
                                //SetAxis(input_event.value * 32767/1023, 1, HID_USAGE_Z);
                            }
                            else if (input_event.code == 16)
                            {
                                if (input_event.value == -1){
                                    SetBtn(1, 1, 125);
                                    SetBtn(0, 1, 126);
                                }
                                else if (input_event.value == 1){
                                    SetBtn(0, 1, 125);
                                    SetBtn(1, 1, 126);
                                }
                                else{
                                    SetBtn(0, 1, 125);
                                    SetBtn(0, 1, 126);
                                }
                            }
                            else if (input_event.code == 17)
                            {
                                if (input_event.value == -1){
                                    SetBtn(1, 1, 127);
                                    SetBtn(0, 1, 128);
                                }
                                else if (input_event.value == 1){
                                    SetBtn(0, 1, 127);
                                    SetBtn(1, 1, 128);
                                }
                                else{
                                    SetBtn(0, 1, 127);
                                    SetBtn(0, 1, 128);
                                }
                            }
                        }
                    }
                }
            }
        }
        
    } while (rx_length > 0);
    
    test.Close();

    // This function seems to work
    std::cout << ResetButtons(1) << std::endl;
    // I never set and Povs, so who knows
    std::cout << ResetPovs(1) << std::endl;

    SetAxis(INT16_MAX, 1, HID_USAGE_X);
    SetAxis(INT16_MAX, 1, HID_USAGE_Y);
    SetAxis(INT16_MAX, 1, HID_USAGE_Z);
    SetAxis(0, 1, HID_USAGE_RX);
    SetAxis(0, 1, HID_USAGE_RX);
    SetAxis(INT16_MAX, 1, HID_USAGE_RZ);
    SetAxis(0, 1, HID_USAGE_SL0);
    SetAxis(0, 1, HID_USAGE_SL1);
    
    RelinquishVJD(1);
    return 0;
}
