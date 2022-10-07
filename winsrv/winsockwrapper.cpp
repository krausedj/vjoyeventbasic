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

#define DEFAULT_PORT "63245"

typedef struct{
    SOCKET ListenSocket = INVALID_SOCKET;
    SOCKET ClientSocket = INVALID_SOCKET;
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
    WSADATA wsaData;
    int iResult;
    struct addrinfo *result = NULL;
    struct addrinfo hints;
    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed with error: %d\n", iResult);
        return 1;
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    // Resolve the server address and port
    iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result);
    if ( iResult != 0 ) {
        printf("getaddrinfo failed with error: %d\n", iResult);
        WSACleanup();
        return 1;
    }

    // Create a SOCKET for the server to listen for client connections.
    DATA->ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (DATA->ListenSocket == INVALID_SOCKET) {
        printf("socket failed with error: %ld\n", WSAGetLastError());
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }

    // Setup the TCP listening socket
    iResult = bind( DATA->ListenSocket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        printf("bind failed with error: %d\n", WSAGetLastError());
        freeaddrinfo(result);
        closesocket(DATA->ListenSocket);
        WSACleanup();
        return 1;
    }

    freeaddrinfo(result);

    iResult = listen(DATA->ListenSocket, SOMAXCONN);
    if (iResult == SOCKET_ERROR) {
        printf("listen failed with error: %d\n", WSAGetLastError());
        closesocket(DATA->ListenSocket);
        WSACleanup();
        return 1;
    }

    // Accept a client socket
    DATA->ClientSocket = accept(DATA->ListenSocket, NULL, NULL);
    if (DATA->ClientSocket == INVALID_SOCKET) {
        printf("accept failed with error: %d\n", WSAGetLastError());
        closesocket(DATA->ListenSocket);
        WSACleanup();
        return 1;
    }

    // No longer need server socket
    closesocket(DATA->ListenSocket);

    return 0;
}

int SockSimple::ReceiveData(void * buffer, const int buffer_len){
    int iResult;
    int iSendResult;

    iResult = recv(DATA->ClientSocket, static_cast<char *>(buffer), buffer_len, 0);
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
        closesocket(DATA->ClientSocket);
        WSACleanup();
        return -1;
    }

    return iResult;
}

int SockSimple::Close(){
    int iResult;
    // shutdown the connection since we're done
    iResult = shutdown(DATA->ClientSocket, SD_SEND);
    if (iResult == SOCKET_ERROR) {
        printf("shutdown failed with error: %d\n", WSAGetLastError());
        closesocket(DATA->ClientSocket);
        WSACleanup();
        return 1;
    }

    // cleanup
    closesocket(DATA->ClientSocket);
    WSACleanup();

    return 0;
}
