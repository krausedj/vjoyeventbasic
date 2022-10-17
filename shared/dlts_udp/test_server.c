
#include "sock_dlts_udp.h"
#include <stdio.h>

#define BUF_SIZE 2048

int main()
{
    char buffer[BUF_SIZE];
    int rx_len;
    struct SockDltsUdpData * data = SockDltsUdp_CreateServer("", 56666);
    SockDltsUdp_ServerWaitForConn(data);
    SockDltsUdp_Recv(data, buffer, BUF_SIZE, &rx_len);
    printf("%s", buffer);
    SockDltsUdp_Close(data);
    SockDltsUdp_Destroy(data);
}
