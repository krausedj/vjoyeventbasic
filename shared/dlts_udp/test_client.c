
#include "sock_dlts_udp.h"
#include <stdio.h>
#include <string.h>

#define BUF_SIZE 2048

int main()
{
    const char * buffer = "hello world!\n";
    struct SockDltsUdpData * data = SockDltsUdp_CreateClient("127.0.0.1", 56666);
    SockDltsUdp_ClientConn(data);
    SockDltsUdp_Send(data, buffer, strlen(buffer)+1);
    SockDltsUdp_Close(data);
    SockDltsUdp_Destroy(data);
}
