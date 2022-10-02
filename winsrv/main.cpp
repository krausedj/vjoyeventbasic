
#include "vjoywrapper.h"
#include "winsockwrapper.hpp"
#include <iostream>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h> 
//#include <sys/socket.h>
//#include <netinet/in.h>

constexpr int RX_BUF_LENGTH = 512;

int main()
{
    SockSimple test{};
    int rx_length = 0;
    char buffer_data[RX_BUF_LENGTH];
    test.WaitForConnection();
    do
    {
        rx_length = test.ReceiveData(buffer_data, RX_BUF_LENGTH);
    } while (rx_length > 0);
    test.Close();
    std::cout << GetvJoyVersion() << std::endl;
    std::cout << AcquireVJD(1) << std::endl;
    // This function does not seem to work, or the descriptions does not do what I expect from the header file
    std::cout << ResetVJD(1) << std::endl;
    usleep(2000000);

    // Hit some buttons, can view in vJoyMonitor
    SetBtn(1, 1, 1);
    SetBtn(1, 1, 2);
    SetBtn(1, 1, 3);

    usleep(5000000);

    // This function also does not seem to work
    std::cout << "ResetAll();" << std::endl;
    ResetAll();
    usleep(2000000);
    // This function seems to work
    std::cout << ResetButtons(1) << std::endl;
    usleep(2000000);
    // I never set and Povs, so who knows
    std::cout << ResetPovs(1) << std::endl;
    usleep(2000000);
    
    RelinquishVJD(1);
    return 0;
}
