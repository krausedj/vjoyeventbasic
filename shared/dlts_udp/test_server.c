
#include "sock_dtls_udp.h"
#include <stdio.h>

#define BUF_SIZE 2048

int main()
{
    char buffer[BUF_SIZE];
    int rx_len;
    printf("Creating Server\n");
    struct SockDtlsUdpData * data = SockDtlsUdp_CreateServer("192.168.35.111", 56666);
    printf("Waiting for Client\n");
    SockDtlsUdp_ServerWaitForConn(data);
    printf("Receive\n");
    SockDtlsUdp_Recv(data, buffer, BUF_SIZE, &rx_len);
    printf("%s", buffer);
    printf("Close\n");
    SockDtlsUdp_Close(data);
    printf("Destroy\n");
    SockDtlsUdp_Destroy(data);
}
