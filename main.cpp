
#include "vjoywrapper.h"
#include <iostream>
#include <unistd.h>

int main()
{
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
