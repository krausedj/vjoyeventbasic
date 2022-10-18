
#ifdef __cplusplus
extern "C" {
#endif

#ifndef SOCK_DTLS_UDP_H__
#define SOCK_DTLS_UDP_H__

typedef int SockDtlsUdp_Status;
#define SockDtlsUdp_ERROR_NONE                      ((SockDtlsUdp_Status)0)
#define SockDtlsUdp_ERROR_UNKNOWN                   ((SockDtlsUdp_Status)1)
#define SockDtlsUdp_SSL_ERROR_WANT_READ             ((SockDtlsUdp_Status)2)
#define SockDtlsUdp_SSL_ERROR_ZERO_RETURN           ((SockDtlsUdp_Status)3)
#define SockDtlsUdp_SSL_ERROR_SYSCALL_UNHANDLED     ((SockDtlsUdp_Status)4)
#define SockDtlsUdp_SSL_ERROR_SYSCALL_HANDLED       ((SockDtlsUdp_Status)5)
#define SockDtlsUdp_SSL_ERROR_SSL                   ((SockDtlsUdp_Status)6)
#define SockDtlsUdp_SSL_ERROR_WANT_WRITE            ((SockDtlsUdp_Status)7)
#define SockDtlsUdp_ERROR_LOCAL_ADDR                ((SockDtlsUdp_Status)8)
#define SockDtlsUdp_ERROR_SOCKET                    ((SockDtlsUdp_Status)9)
#define SockDtlsUdp_ERROR_BIND                      ((SockDtlsUdp_Status)10)
#define SockDtlsUdp_ERROR_CONNECT                   ((SockDtlsUdp_Status)11)
#define SockDtlsUdp_ERROR_SSL_ACCEPT                ((SockDtlsUdp_Status)12)
#define SockDtlsUdp_ERROR_REMOTE_ADDR               ((SockDtlsUdp_Status)13)
#define SockDtlsUdp_SSL_ERROR_WANT_CONNECT          ((SockDtlsUdp_Status)14)
#define SockDtlsUdp_SSL_ERROR_WANT_ACCEPT           ((SockDtlsUdp_Status)15)
#define SockDtlsUdp_SSL_ERROR_WANT_X509_LOOKUP      ((SockDtlsUdp_Status)16)


//Highly hide the winsock2 vs unix socket
struct SockDtlsUdpData * SockDtlsUdp_CreateServer(char * local_address, int port);
struct SockDtlsUdpData * SockDtlsUdp_CreateClient(char * remote_address, int port);
void SockDtlsUdp_Close(struct SockDtlsUdpData * data);
void SockDtlsUdp_Destroy(struct SockDtlsUdpData * data);

SockDtlsUdp_Status SockDtlsUdp_ClientConn(struct SockDtlsUdpData * data);
SockDtlsUdp_Status SockDtlsUdp_ServerWaitForConn(struct SockDtlsUdpData * data);
SockDtlsUdp_Status SockDtlsUdp_Recv(struct SockDtlsUdpData * data, void * buffer, const int buffer_len, int * rx_len);
SockDtlsUdp_Status SockDtlsUdp_Send(struct SockDtlsUdpData * data, const void * buffer, const int buffer_len);

#endif /* SOCK_DTLS_UDP_H__ */

#ifdef __cplusplus
}
#endif
