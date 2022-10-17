
#ifdef __cplusplus
extern "C" {
#endif

#ifndef SOCK_DLTS_UDP_H__
#define SOCK_DLTS_UDP_H__

typedef int SockDltsUdp_Status;
#define SockDltsUdp_ERROR_NONE                      ((SockDltsUdp_Status)0)
#define SockDltsUdp_ERROR_UNKNOWN                   ((SockDltsUdp_Status)1)
#define SockDltsUdp_SSL_ERROR_WANT_READ             ((SockDltsUdp_Status)2)
#define SockDltsUdp_SSL_ERROR_ZERO_RETURN           ((SockDltsUdp_Status)3)
#define SockDltsUdp_SSL_ERROR_SYSCALL_UNHANDLED     ((SockDltsUdp_Status)4)
#define SockDltsUdp_SSL_ERROR_SYSCALL_HANDLED       ((SockDltsUdp_Status)5)
#define SockDltsUdp_SSL_ERROR_SSL                   ((SockDltsUdp_Status)6)
#define SockDltsUdp_SSL_ERROR_WANT_WRITE            ((SockDltsUdp_Status)7)
#define SockDltsUdp_ERROR_LOCAL_ADDR                ((SockDltsUdp_Status)8)
#define SockDltsUdp_ERROR_SOCKET                    ((SockDltsUdp_Status)9)
#define SockDltsUdp_ERROR_BIND                      ((SockDltsUdp_Status)10)
#define SockDltsUdp_ERROR_CONNECT                   ((SockDltsUdp_Status)11)
#define SockDltsUdp_ERROR_SSL_ACCEPT                ((SockDltsUdp_Status)12)
#define SockDltsUdp_ERROR_REMOTE_ADDR               ((SockDltsUdp_Status)13)
#define SockDltsUdp_SSL_ERROR_WANT_CONNECT          ((SockDltsUdp_Status)14)
#define SockDltsUdp_SSL_ERROR_WANT_ACCEPT           ((SockDltsUdp_Status)15)
#define SockDltsUdp_SSL_ERROR_WANT_X509_LOOKUP      ((SockDltsUdp_Status)16)


//Highly hide the winsock2 vs unix socket
struct SockDltsUdpData * SockDltsUdp_CreateServer(char * local_address, int port);
struct SockDltsUdpData * SockDltsUdp_CreateClient(char * remote_address, int port);
void SockDltsUdp_Close(struct SockDltsUdpData * data);
void SockDltsUdp_Destroy(struct SockDltsUdpData * data);

SockDltsUdp_Status SockDltsUdp_ClientConn(struct SockDltsUdpData * data);
SockDltsUdp_Status SockDltsUdp_ServerWaitForConn(struct SockDltsUdpData * data);
SockDltsUdp_Status SockDltsUdp_Recv(struct SockDltsUdpData * data, void * buffer, const int buffer_len, int * rx_len);
SockDltsUdp_Status SockDltsUdp_Send(struct SockDltsUdpData * data, const void * buffer, const int buffer_len);

#endif /* SOCK_DLTS_UDP_H__ */

#ifdef __cplusplus
}
#endif
