#undef UNICODE

#define WIN32_LEAN_AND_MEAN

#include "winsockwrapper.hpp"
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>

// Need to link with Ws2_32.lib
#pragma comment (lib, "Ws2_32.lib")
// #pragma comment (lib, "Mswsock.lib")

#define DEFAULT_PORT 63245

typedef struct{
    SOCKET Socket = INVALID_SOCKET;
} SockSimpleData;

//Lazy pImpl implementation
#define DATA (static_cast<SockSimpleData *>(static_cast<void *>(_data)))

SockSimple::SockSimple(){
    _data = static_cast<SockSimpleDataStruct*>(static_cast<void *>((new SockSimpleData())));
}

SockSimple::~SockSimple(){
    SockSimpleData * del_data = DATA;
    delete del_data;
}

int SockSimple::WaitForConnection(){
	struct sockaddr_in server, si_other;
	int slen , recv_len;
	WSADATA wsa;

	slen = sizeof(si_other) ;
	
	//Initialise winsock
	printf("\nInitialising Winsock...");
	if (WSAStartup(MAKEWORD(2,2),&wsa) != 0)
	{
		printf("Failed. Error Code : %d",WSAGetLastError());
		return 1;
	}
	printf("Initialised.\n");
	
	//Create a socket
	if((DATA->Socket = socket(AF_INET , SOCK_DGRAM , 0 )) == INVALID_SOCKET)
	{
		printf("Could not create socket : %d" , WSAGetLastError());
        return 1;
	}
	printf("Socket created.\n");
	
	//Prepare the sockaddr_in structure
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port = htons( DEFAULT_PORT );
	
	//Bind
	if( bind(DATA->Socket ,(struct sockaddr *)&server , sizeof(server)) == SOCKET_ERROR)
	{
		printf("Bind failed with error code : %d" , WSAGetLastError());
		return 1;
	}
	puts("Bind done");
    
    return 0;
}

int SockSimple::ReceiveData(void * buffer, const int buffer_len){
    int iResult;
    int iSendResult;

    iResult = recv(DATA->Socket, static_cast<char *>(buffer), buffer_len, 0);
    if (iResult > 0) {
#if 0
        printf("Bytes received: %d\n", iResult);
        // Echo the buffer back to the sender
        iSendResult = send( DATA->ClientSocket, static_cast<char *>(buffer), iResult, 0 );
        if (iSendResult == SOCKET_ERROR) {
            printf("send failed with error: %d\n", WSAGetLastError());
            closesocket(DATA->ClientSocket);
            WSACleanup();
            return -1;
        }
        printf("Bytes sent: %d\n", iSendResult);
#endif
    }
    else if (iResult == 0)
        printf("Connection closing...\n");
    else  {
        printf("recv failed with error: %d\n", WSAGetLastError());
        closesocket(DATA->Socket);
        WSACleanup();
        return -1;
    }

    return iResult;
}

int SockSimple::Close(){
    int iResult;
    // shutdown the connection since we're done
    iResult = shutdown(DATA->Socket, SD_SEND);
    if (iResult == SOCKET_ERROR) {
        printf("shutdown failed with error: %d\n", WSAGetLastError());
        closesocket(DATA->Socket);
        WSACleanup();
        return 1;
    }

    // cleanup
    closesocket(DATA->Socket);
    WSACleanup();

    return 0;
}
