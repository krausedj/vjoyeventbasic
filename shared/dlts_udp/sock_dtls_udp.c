/*
 * Copyright (C) 2009 - 2012 Robin Seggelmann, seggelmann@fh-muenster.de,
 *                           Michael Tuexen, tuexen@fh-muenster.de
 *               2019 Felix Weinrank, weinrank@fh-muenster.de
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * Copyright 2022 Daniel J. Krause, krausedj@gmail.com
 *   Original file: https://raw.githubusercontent.com/nplab/DTLS-Examples/master/src/dtls_udp_echo.c
 *   Modification are to enable this to be a bit more abstracted for use in additional applications.
 *   Conditions from original copyright holders apply.
 */

#ifdef WIN32
#include <winsock2.h>
#include <Ws2tcpip.h>
#define in_port_t u_short
#define ssize_t int
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#endif

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/opensslv.h>

#include "sock_dtls_udp.h"

#define BUFFER_SIZE          (1<<16)
#define COOKIE_SECRET_LENGTH 16

#define DEFAULT_PORT 63245

struct SockDtlsUdpData{
	SSL *ssl;
    int verbose;
    int veryverbose;
    int fd;
    int num_timeouts;
    int max_timeouts;
	int num_errors;
    struct timeval startup_timeout;
    struct timeval rx_timeout;
    int port;
    char local_address[INET6_ADDRSTRLEN+1];
    char remote_address[INET6_ADDRSTRLEN+1];
};

/* Common cookie for now */
unsigned char cookie_secret[COOKIE_SECRET_LENGTH];
int cookie_initialized;

int handle_socket_error() {
	switch (errno) {
		case EINTR:
			/* Interrupted system call.
			 * Just ignore.
			 */
			printf("Interrupted system call!\n");
			return 1;
		case EBADF:
			/* Invalid socket.
			 * Must close connection.
			 */
			printf("Invalid socket!\n");
			return 0;
			break;
#ifdef EHOSTDOWN
		case EHOSTDOWN:
			/* Host is down.
			 * Just ignore, might be an attacker
			 * sending fake ICMP messages.
			 */
			printf("Host is down!\n");
			return 1;
#endif
#ifdef ECONNRESET
		case ECONNRESET:
			/* Connection reset by peer.
			 * Just ignore, might be an attacker
			 * sending fake ICMP messages.
			 */
			printf("Connection reset by peer!\n");
			return 1;
#endif
		case ENOMEM:
			/* Out of memory.
			 * Must close connection.
			 */
			printf("Out of memory!\n");
			return 0;
			break;
		case EACCES:
			/* Permission denied.
			 * Just ignore, we might be blocked
			 * by some firewall policy. Try again
			 * and hope for the best.
			 */
			printf("Permission denied!\n");
			return 1;
			break;
		default:
			/* Something unexpected happened */
			printf("Unexpected error! (errno = %d)\n", errno);
			return 0;
			break;
	}
	return 0;
}

int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
{
	unsigned char *buffer, result[EVP_MAX_MD_SIZE];
	unsigned int length = 0, resultlength;
	union {
		struct sockaddr_storage ss;
		struct sockaddr_in6 s6;
		struct sockaddr_in s4;
	} peer;

	/* Initialize a random secret */
	if (!cookie_initialized)
		{
		if (!RAND_bytes(cookie_secret, COOKIE_SECRET_LENGTH))
			{
			printf("error setting random cookie secret\n");
			return 0;
			}
		cookie_initialized = 1;
		}

	/* Read peer information */
	(void) BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

	/* Create buffer with peer's address and port */
	length = 0;
	switch (peer.ss.ss_family) {
		case AF_INET:
			length += sizeof(struct in_addr);
			break;
		case AF_INET6:
			length += sizeof(struct in6_addr);
			break;
		default:
			OPENSSL_assert(0);
			break;
	}
	length += sizeof(in_port_t);
	buffer = (unsigned char*) OPENSSL_malloc(length);

	if (buffer == NULL)
		{
		printf("out of memory\n");
		return 0;
		}

	switch (peer.ss.ss_family) {
		case AF_INET:
			memcpy(buffer,
				   &peer.s4.sin_port,
				   sizeof(in_port_t));
			memcpy(buffer + sizeof(peer.s4.sin_port),
				   &peer.s4.sin_addr,
				   sizeof(struct in_addr));
			break;
		case AF_INET6:
			memcpy(buffer,
				   &peer.s6.sin6_port,
				   sizeof(in_port_t));
			memcpy(buffer + sizeof(in_port_t),
				   &peer.s6.sin6_addr,
				   sizeof(struct in6_addr));
			break;
		default:
			OPENSSL_assert(0);
			break;
	}

	/* Calculate HMAC of buffer using the secret */
	HMAC(EVP_sha1(), (const void*) cookie_secret, COOKIE_SECRET_LENGTH,
		 (const unsigned char*) buffer, length, result, &resultlength);
	OPENSSL_free(buffer);

	memcpy(cookie, result, resultlength);
	*cookie_len = resultlength;

	return 1;
}

int verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len)
{
	unsigned char *buffer, result[EVP_MAX_MD_SIZE];
	unsigned int length = 0, resultlength;
	union {
		struct sockaddr_storage ss;
		struct sockaddr_in6 s6;
		struct sockaddr_in s4;
	} peer;

	/* If secret isn't initialized yet, the cookie can't be valid */
	if (!cookie_initialized)
		return 0;

	/* Read peer information */
	(void) BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

	/* Create buffer with peer's address and port */
	length = 0;
	switch (peer.ss.ss_family) {
		case AF_INET:
			length += sizeof(struct in_addr);
			break;
		case AF_INET6:
			length += sizeof(struct in6_addr);
			break;
		default:
			OPENSSL_assert(0);
			break;
	}
	length += sizeof(in_port_t);
	buffer = (unsigned char*) OPENSSL_malloc(length);

	if (buffer == NULL)
		{
		printf("out of memory\n");
		return 0;
		}

	switch (peer.ss.ss_family) {
		case AF_INET:
			memcpy(buffer,
				   &peer.s4.sin_port,
				   sizeof(in_port_t));
			memcpy(buffer + sizeof(in_port_t),
				   &peer.s4.sin_addr,
				   sizeof(struct in_addr));
			break;
		case AF_INET6:
			memcpy(buffer,
				   &peer.s6.sin6_port,
				   sizeof(in_port_t));
			memcpy(buffer + sizeof(in_port_t),
				   &peer.s6.sin6_addr,
				   sizeof(struct in6_addr));
			break;
		default:
			OPENSSL_assert(0);
			break;
	}

	/* Calculate HMAC of buffer using the secret */
	HMAC(EVP_sha1(), (const void*) cookie_secret, COOKIE_SECRET_LENGTH,
		 (const unsigned char*) buffer, length, result, &resultlength);
	OPENSSL_free(buffer);

	if (cookie_len == resultlength && memcmp(result, cookie, resultlength) == 0)
		return 1;

	return 0;
}

int dtls_verify_callback (int ok, X509_STORE_CTX *ctx) {
	/* This function should ask the user
	 * if he trusts the received certificate.
	 * Here we always trust.
	 */
	return 1;
}

SockDtlsUdp_Status SockDtlsUdp_ServerWaitForConn(struct SockDtlsUdpData * data){
#if WIN32
	WSADATA wsaData;
#endif
	SSL_CTX *ctx;
	BIO *bio;
	struct timeval timeout;
	const int on = 1, off = 0;
    int ret;

    union {
		struct sockaddr_storage ss;
		struct sockaddr_in6 s6;
		struct sockaddr_in s4;
	} server_addr, client_addr;

	memset(&server_addr, 0, sizeof(struct sockaddr_storage));
	if (strlen(data->local_address) == 0) {
		server_addr.s6.sin6_family = AF_INET6;
#ifdef HAVE_SIN6_LEN
		data->server_addr.s6.sin6_len = sizeof(struct sockaddr_in6);
#endif
		server_addr.s6.sin6_addr = in6addr_any;
		server_addr.s6.sin6_port = htons(data->port);
	} else {
		if (inet_pton(AF_INET, data->local_address, &server_addr.s4.sin_addr) == 1) {
			server_addr.s4.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
			server_addr.s4.sin_len = sizeof(struct sockaddr_in);
#endif
			server_addr.s4.sin_port = htons(data->port);
		} else if (inet_pton(AF_INET6, data->local_address, &server_addr.s6.sin6_addr) == 1) {
			server_addr.s6.sin6_family = AF_INET6;
#ifdef HAVE_SIN6_LEN
			server_addr.s6.sin6_len = sizeof(struct sockaddr_in6);
#endif
			server_addr.s6.sin6_port = htons(data->port);
		} else {
			return SockDtlsUdp_ERROR_LOCAL_ADDR;
		}
	}

	OpenSSL_add_ssl_algorithms();
	SSL_load_error_strings();
	ctx = SSL_CTX_new(DTLS_server_method());
	/* We accept all ciphers, including NULL.
	 * Not recommended beyond testing and debugging
	 */
	//SSL_CTX_set_cipher_list(ctx, "ALL:NULL:eNULL:aNULL");
	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

	if (!SSL_CTX_use_certificate_file(ctx, "certs/server-cert.pem", SSL_FILETYPE_PEM))
		printf("\nERROR: no certificate found!");

	if (!SSL_CTX_use_PrivateKey_file(ctx, "certs/server-key.pem", SSL_FILETYPE_PEM))
		printf("\nERROR: no private key found!");

	if (!SSL_CTX_check_private_key (ctx))
		printf("\nERROR: invalid private key!");

	/* Client has to authenticate */
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, dtls_verify_callback);

	SSL_CTX_set_read_ahead(ctx, 1);
	SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
	SSL_CTX_set_cookie_verify_cb(ctx, &verify_cookie);

#ifdef WIN32
	WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

	data->fd = socket(server_addr.ss.ss_family, SOCK_DGRAM, 0);
	if (data->fd < 0) {
		perror("socket");
		return SockDtlsUdp_ERROR_SOCKET;
	}

#ifdef WIN32
	setsockopt(data->fd, SOL_SOCKET, SO_REUSEADDR, (const char*) &on, (socklen_t) sizeof(on));
#else
	setsockopt(data->fd, SOL_SOCKET, SO_REUSEADDR, (const void*) &on, (socklen_t) sizeof(on));
#if defined(SO_REUSEPORT) && !defined(__linux__)
	setsockopt(data->fd, SOL_SOCKET, SO_REUSEPORT, (const void*) &on, (socklen_t) sizeof(on));
#endif
#endif

	if (server_addr.ss.ss_family == AF_INET) {
		if (bind(data->fd, (const struct sockaddr *) &server_addr, sizeof(struct sockaddr_in))) {
			perror("bind");
			return SockDtlsUdp_ERROR_BIND;
		}
	} else {
		setsockopt(data->fd, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&off, sizeof(off));
		if (bind(data->fd, (const struct sockaddr *) &server_addr, sizeof(struct sockaddr_in6))) {
			perror("bind");
			return SockDtlsUdp_ERROR_BIND;
		}
	}

    memset(&client_addr, 0, sizeof(struct sockaddr_storage));

    /* Create BIO */
    bio = BIO_new_dgram(data->fd, BIO_NOCLOSE);

    /* Set and activate timeouts */
    timeout = data->startup_timeout;
    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

    data->ssl = SSL_new(ctx);

    SSL_set_bio(data->ssl, bio, bio);
    SSL_set_options(data->ssl, SSL_OP_COOKIE_EXCHANGE);
printf("1\n");
    while (DTLSv1_listen(data->ssl, (BIO_ADDR *) &client_addr) <= 0);
printf("2\n");
	char addrbuf[INET6_ADDRSTRLEN];

	OPENSSL_assert(client_addr.ss.ss_family == server_addr.ss.ss_family);
	data->fd = socket(client_addr.ss.ss_family, SOCK_DGRAM, 0);
	if (data->fd < 0) {
		perror("socket");
		return SockDtlsUdp_ERROR_SOCKET;
	}
printf("3\n");
#ifdef WIN32
	setsockopt(data->fd, SOL_SOCKET, SO_REUSEADDR, (const char*) &on, (socklen_t) sizeof(on));
#else
	setsockopt(data->fd, SOL_SOCKET, SO_REUSEADDR, (const void*) &on, (socklen_t) sizeof(on));
#if defined(SO_REUSEPORT) && !defined(__linux__)
	setsockopt(data->fd, SOL_SOCKET, SO_REUSEPORT, (const void*) &on, (socklen_t) sizeof(on));
#endif
#endif
	switch (client_addr.ss.ss_family) {
		case AF_INET:
			if (bind(data->fd, (const struct sockaddr *) &server_addr, sizeof(struct sockaddr_in))) {
				perror("bind");
				return SockDtlsUdp_ERROR_BIND;
			}
			if (connect(data->fd, (struct sockaddr *) &client_addr, sizeof(struct sockaddr_in))) {
				perror("connect");
				return SockDtlsUdp_ERROR_CONNECT;
			}
			break;
		case AF_INET6:
			setsockopt(data->fd, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&off, sizeof(off));
			if (bind(data->fd, (const struct sockaddr *) &server_addr, sizeof(struct sockaddr_in6))) {
				perror("bind");
				return SockDtlsUdp_ERROR_BIND;
			}
			if (connect(data->fd, (struct sockaddr *) &client_addr, sizeof(struct sockaddr_in6))) {
				perror("connect");
				return SockDtlsUdp_ERROR_CONNECT;
			}
			break;
		default:
			OPENSSL_assert(0);
			break;
	}
printf("4\n");
	/* Set new fd and set BIO to connected */
	BIO_set_fd(SSL_get_rbio(data->ssl), data->fd, BIO_NOCLOSE);
	BIO_ctrl(SSL_get_rbio(data->ssl), BIO_CTRL_DGRAM_SET_CONNECTED, 0, &client_addr.ss);
printf("%i\n", client_addr.s4.sin_port);
printf("%i\n", client_addr.s4.sin_addr);
printf("5\n");
	/* Finish handshake */
	do { ret = SSL_accept(data->ssl); }
	while (ret == 0);
	if (ret < 0) {
        char buf[BUFFER_SIZE];
		perror("SSL_accept");
		printf("%s\n", ERR_error_string(ERR_get_error(), buf));
		return SockDtlsUdp_ERROR_SSL_ACCEPT;
	}
printf("6\n");
    timeout = data->startup_timeout;
	BIO_ctrl(SSL_get_rbio(data->ssl), BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

	if (data->verbose) {
		if (client_addr.ss.ss_family == AF_INET) {
			printf ("\naccepted connection from %s:%d\n",
					inet_ntop(AF_INET, &client_addr.s4.sin_addr, addrbuf, INET6_ADDRSTRLEN),
					ntohs(client_addr.s4.sin_port));
		} else {
			printf ("\naccepted connection from %s:%d\n",
					inet_ntop(AF_INET6, &client_addr.s6.sin6_addr, addrbuf, INET6_ADDRSTRLEN),
					ntohs(client_addr.s6.sin6_port));
		}
	}
printf("7\n");
	if (data->veryverbose && SSL_get_peer_certificate(data->ssl)) {
		printf ("------------------------------------------------------------\n");
		X509_NAME_print_ex_fp(stdout, X509_get_subject_name(SSL_get_peer_certificate(data->ssl)),
							  1, XN_FLAG_MULTILINE);
		printf("\n\n Cipher: %s", SSL_CIPHER_get_name(SSL_get_current_cipher(data->ssl)));
		printf ("\n------------------------------------------------------------\n\n");
	}

	return SockDtlsUdp_ERROR_NONE;
}

SockDtlsUdp_Status SockDtlsUdp_Recv(struct SockDtlsUdpData * data, void * buffer, const int buffer_len, int * rx_len){
    SockDtlsUdp_Status status = SockDtlsUdp_ERROR_UNKNOWN;
    struct timeval timeout = data->rx_timeout;
	BIO_ctrl(SSL_get_rbio(data->ssl), BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);
    *rx_len = (int)SSL_read(data->ssl, buffer, buffer_len);


    switch (SSL_get_error(data->ssl, *rx_len)) {
        case SSL_ERROR_NONE:
            if (data->verbose) {
                printf("read %d bytes\n", (int) *rx_len);
            }
			status = SockDtlsUdp_ERROR_NONE;
            break;
        case SSL_ERROR_WANT_READ:
            /* Handle socket timeouts */
            if (BIO_ctrl(SSL_get_rbio(data->ssl), BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP, 0, NULL)) {
                data->num_timeouts++;
            }
			else{
				data->num_errors++;
			}
			status = SockDtlsUdp_SSL_ERROR_WANT_READ;
            break;
        case SSL_ERROR_ZERO_RETURN:
			status = SockDtlsUdp_SSL_ERROR_ZERO_RETURN;
			data->num_errors++;
            break;
        case SSL_ERROR_SYSCALL:
            printf("Socket read error: ");
			data->num_errors++;
            if (!handle_socket_error()){
				status = SockDtlsUdp_SSL_ERROR_SYSCALL_UNHANDLED;
			}
			else {
				status = SockDtlsUdp_SSL_ERROR_SYSCALL_HANDLED;
			}
            break;
        case SSL_ERROR_SSL:
            printf("SSL read error: ");
            printf("%s (%d)\n", ERR_error_string(ERR_get_error(), buffer), SSL_get_error(data->ssl, *rx_len));
            status = SockDtlsUdp_SSL_ERROR_SSL;
            break;
        default:
            printf("Unexpected error while reading!\n");
            status = SockDtlsUdp_ERROR_UNKNOWN;
            break;
    }

    return status;
}

SockDtlsUdp_Status SockDtlsUdp_ClientConn(struct SockDtlsUdpData * data){
	int retval;
	char buf[BUFFER_SIZE];
	char addrbuf[INET6_ADDRSTRLEN];
	socklen_t len;
	SSL_CTX *ctx;
	BIO *bio;
	struct timeval timeout;
#if WIN32
	WSADATA wsaData;
#endif

	union {
		struct sockaddr_storage ss;
		struct sockaddr_in6 s6;
		struct sockaddr_in s4;
	} remote_addr, local_addr;

	memset((void *) &remote_addr, 0, sizeof(struct sockaddr_storage));
	memset((void *) &local_addr, 0, sizeof(struct sockaddr_storage));

	if (inet_pton(AF_INET, data->remote_address, &remote_addr.s4.sin_addr) == 1) {
		remote_addr.s4.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
		remote_addr.s4.sin_len = sizeof(struct sockaddr_in);
#endif
		remote_addr.s4.sin_port = htons(data->port);
	} else if (inet_pton(AF_INET6, data->remote_address, &remote_addr.s6.sin6_addr) == 1) {
		remote_addr.s6.sin6_family = AF_INET6;
#ifdef HAVE_SIN6_LEN
		remote_addr.s6.sin6_len = sizeof(struct sockaddr_in6);
#endif
		remote_addr.s6.sin6_port = htons(data->port);
	} else {
		return SockDtlsUdp_ERROR_REMOTE_ADDR;
	}

#ifdef WIN32
	WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

	data->fd = socket(remote_addr.ss.ss_family, SOCK_DGRAM, 0);
	if (data->fd < 0) {
		perror("socket");
		return SockDtlsUdp_ERROR_SOCKET;
	}

	if (strlen(data->local_address) > 0) {
		if (inet_pton(AF_INET, data->local_address, &local_addr.s4.sin_addr) == 1) {
			local_addr.s4.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
			local_addr.s4.sin_len = sizeof(struct sockaddr_in);
#endif
			local_addr.s4.sin_port = htons(0);
		} else if (inet_pton(AF_INET6, data->local_address, &local_addr.s6.sin6_addr) == 1) {
			local_addr.s6.sin6_family = AF_INET6;
#ifdef HAVE_SIN6_LEN
			local_addr.s6.sin6_len = sizeof(struct sockaddr_in6);
#endif
			local_addr.s6.sin6_port = htons(0);
		} else {
			return SockDtlsUdp_ERROR_LOCAL_ADDR;
		}
		OPENSSL_assert(remote_addr.ss.ss_family == local_addr.ss.ss_family);
		if (local_addr.ss.ss_family == AF_INET) {
			if (bind(data->fd, (const struct sockaddr *) &local_addr, sizeof(struct sockaddr_in))) {
				perror("bind");
				return SockDtlsUdp_ERROR_BIND;
			}
		} else {
			if (bind(data->fd, (const struct sockaddr *) &local_addr, sizeof(struct sockaddr_in6))) {
				perror("bind");
				return SockDtlsUdp_ERROR_BIND;
			}
		}
	}

	OpenSSL_add_ssl_algorithms();
	SSL_load_error_strings();
	ctx = SSL_CTX_new(DTLS_client_method());
	//SSL_CTX_set_cipher_list(ctx, "eNULL:!MD5");

	if (!SSL_CTX_use_certificate_file(ctx, "certs/client-cert.pem", SSL_FILETYPE_PEM))
		printf("\nERROR: no certificate found!");

	if (!SSL_CTX_use_PrivateKey_file(ctx, "certs/client-key.pem", SSL_FILETYPE_PEM))
		printf("\nERROR: no private key found!");

	if (!SSL_CTX_check_private_key (ctx))
		printf("\nERROR: invalid private key!");

	SSL_CTX_set_verify_depth (ctx, 2);
	SSL_CTX_set_read_ahead(ctx, 1);


	data->ssl = SSL_new(ctx);

	/* Create BIO, connect and set to already connected */
	bio = BIO_new_dgram(data->fd, BIO_CLOSE);
	if (remote_addr.ss.ss_family == AF_INET) {
		if (connect(data->fd, (struct sockaddr *) &remote_addr, sizeof(struct sockaddr_in))) {
			perror("connect");
            return SockDtlsUdp_ERROR_CONNECT;
		}
	} else {
		if (connect(data->fd, (struct sockaddr *) &remote_addr, sizeof(struct sockaddr_in6))) {
			perror("connect");
            return SockDtlsUdp_ERROR_CONNECT;
		}
	}
	BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &remote_addr.ss);

	SSL_set_bio(data->ssl, bio, bio);

	retval = SSL_connect(data->ssl);
	if (retval <= 0) {
		switch (SSL_get_error(data->ssl, retval)) {
			case SSL_ERROR_ZERO_RETURN:
				fprintf(stderr, "SSL_connect failed with SSL_ERROR_ZERO_RETURN\n");
                return SockDtlsUdp_SSL_ERROR_ZERO_RETURN;
				break;
			case SSL_ERROR_WANT_READ:
				fprintf(stderr, "SSL_connect failed with SSL_ERROR_WANT_READ\n");
                return SockDtlsUdp_SSL_ERROR_WANT_READ;
				break;
			case SSL_ERROR_WANT_WRITE:
				fprintf(stderr, "SSL_connect failed with SSL_ERROR_WANT_WRITE\n");
                return SockDtlsUdp_SSL_ERROR_WANT_WRITE;
				break;
			case SSL_ERROR_WANT_CONNECT:
				fprintf(stderr, "SSL_connect failed with SSL_ERROR_WANT_CONNECT\n");
                return SockDtlsUdp_SSL_ERROR_WANT_CONNECT;
				break;
			case SSL_ERROR_WANT_ACCEPT:
				fprintf(stderr, "SSL_connect failed with SSL_ERROR_WANT_ACCEPT\n");
                return SockDtlsUdp_SSL_ERROR_WANT_ACCEPT;
				break;
			case SSL_ERROR_WANT_X509_LOOKUP:
				fprintf(stderr, "SSL_connect failed with SSL_ERROR_WANT_X509_LOOKUP\n");
                return SockDtlsUdp_SSL_ERROR_WANT_X509_LOOKUP;
				break;
			case SSL_ERROR_SYSCALL:
				fprintf(stderr, "SSL_connect failed with SSL_ERROR_SYSCALL\n");
                return SockDtlsUdp_SSL_ERROR_SYSCALL_UNHANDLED;
				break;
			case SSL_ERROR_SSL:
				fprintf(stderr, "SSL_connect failed with SSL_ERROR_SSL\n");
                return SockDtlsUdp_ERROR_SSL_ACCEPT;
				break;
			default:
				fprintf(stderr, "SSL_connect failed with unknown error\n");
                return SockDtlsUdp_ERROR_UNKNOWN;
				break;
		}
	}

	/* Set and activate timeouts */
	timeout = data->startup_timeout;
	BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

	if (data->verbose) {
		if (remote_addr.ss.ss_family == AF_INET) {
			printf ("\nConnected to %s\n",
					 inet_ntop(AF_INET, &remote_addr.s4.sin_addr, addrbuf, INET6_ADDRSTRLEN));
		} else {
			printf ("\nConnected to %s\n",
					 inet_ntop(AF_INET6, &remote_addr.s6.sin6_addr, addrbuf, INET6_ADDRSTRLEN));
		}
	}

	if (data->veryverbose && SSL_get_peer_certificate(data->ssl)) {
		printf ("------------------------------------------------------------\n");
		X509_NAME_print_ex_fp(stdout, X509_get_subject_name(SSL_get_peer_certificate(data->ssl)),
							  1, XN_FLAG_MULTILINE);
		printf("\n\n Cipher: %s", SSL_CIPHER_get_name(SSL_get_current_cipher(data->ssl)));
		printf ("\n------------------------------------------------------------\n\n");
	}

    return SockDtlsUdp_ERROR_NONE;
}

SockDtlsUdp_Status SockDtlsUdp_Send(struct SockDtlsUdpData * data, const void * buffer, const int buffer_len){
    SockDtlsUdp_Status status = SockDtlsUdp_ERROR_UNKNOWN;
    int len = SSL_write(data->ssl, buffer, buffer_len);

    switch (SSL_get_error(data->ssl, len)) {
        case SSL_ERROR_NONE:
            if (data->verbose) {
                printf("wrote %d bytes\n", (int) len);
            }
            status = SockDtlsUdp_ERROR_NONE;
            break;
        case SSL_ERROR_WANT_WRITE:
            /* Just try again later */
            status = SockDtlsUdp_SSL_ERROR_WANT_WRITE;
            break;
        case SSL_ERROR_WANT_READ:
            /* continue with reading */
            status = SockDtlsUdp_SSL_ERROR_WANT_READ;
            break;
        case SSL_ERROR_SYSCALL:
            printf("Socket write error: ");
            if (!handle_socket_error()){
                status = SockDtlsUdp_SSL_ERROR_SYSCALL_UNHANDLED;
            }
            else {
                status = SockDtlsUdp_SSL_ERROR_SYSCALL_HANDLED;
            }
            //reading = 0;
            break;
        case SSL_ERROR_SSL:
			{
				char buf[BUFFER_SIZE];
				printf("SSL write error: ");
				printf("%s (%d)\n", ERR_error_string(ERR_get_error(), buf), SSL_get_error(data->ssl, len));
				status = SockDtlsUdp_SSL_ERROR_SSL;
			}
            break;
        default:
            printf("Unexpected error while writing!\n");
            status = SockDtlsUdp_ERROR_UNKNOWN;
            break;
    }

    return status;
}

void SockDtlsUdp_Close(struct SockDtlsUdpData * data){
	SSL_shutdown(data->ssl);

#ifdef WIN32
	closesocket(data->fd);
#else
	close(data->fd);
#endif
	SSL_free(data->ssl);
	if (data->verbose)
		printf("connection closed.\n");
#ifdef WIN32
	WSACleanup();
#endif
}

struct SockDtlsUdpData * SockDtlsUdp_CreateServer(char * local_address, int port){
	struct SockDtlsUdpData * data = malloc(sizeof(struct SockDtlsUdpData));
	memset(data, 0, sizeof(struct SockDtlsUdpData));
	/* copy inputs */
	strncpy(data->local_address, local_address, INET6_ADDRSTRLEN+1);
	data->port = port;
    /* Set and activate timeouts */
	data->startup_timeout.tv_sec = 5;
	data->startup_timeout.tv_usec = 0;
	data->rx_timeout.tv_sec = 0;
	data->rx_timeout.tv_usec = 250000;
	
	data->verbose = 1;
	data->veryverbose = 1;

	return data;
}

struct SockDtlsUdpData * SockDtlsUdp_CreateClient(char * remote_address, int port){
	struct SockDtlsUdpData * data = malloc(sizeof(struct SockDtlsUdpData));
	memset(data, 0, sizeof(struct SockDtlsUdpData));
	/* copy inputs */
	strncpy(data->remote_address, remote_address, INET6_ADDRSTRLEN+1);
	data->port = port;
    /* Set and activate timeouts */
	data->startup_timeout.tv_sec = 5;
	data->startup_timeout.tv_usec = 0;
	data->rx_timeout.tv_sec = 0;
	data->rx_timeout.tv_usec = 250000;

	data->verbose = 1;
	data->veryverbose = 1;

	return data;
}

void SockDtlsUdp_Destroy(struct SockDtlsUdpData * data){
	free(data);
}

int SockDtlsUdp_IsSslShutdown(struct SockDtlsUdpData * data){
    return (!(SSL_get_shutdown(data->ssl) & SSL_RECEIVED_SHUTDOWN));
}
