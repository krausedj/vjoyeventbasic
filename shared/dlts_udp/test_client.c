
#include "sock_dtls_udp.h"
#include <stdio.h>
#include <string.h>

#define BUF_SIZE 2048

int main()
{
    const char buffer[BUF_SIZE] = "hello world!\n";
    printf("Creating client\n");
    struct SockDtlsUdpData * data = SockDtlsUdp_CreateClient("192.168.35.111", 56666);
    printf("Connecting\n");
    SockDtlsUdp_ClientConn(data);
    printf("Sending Data\n");
    SockDtlsUdp_Send(data, buffer, strlen(buffer));
    printf("Close\n");
    SockDtlsUdp_Close(data);
    printf("Destroy\n");
    SockDtlsUdp_Destroy(data);
}
