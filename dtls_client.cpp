#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <arpa/inet.h>

#include <thread>

#include <iostream>

#include <openssl/ssl.h>
#include <openssl/bio.h>

#include "dtls_common.h"

int fd = -1;


bool handshake_done_for_us = false;

int main(int ac, const char *av[])
{
    // create udp socket
    fd = socket(AF_INET, SOCK_DGRAM, 0);

    // local address
    struct sockaddr_in la;
    memset(&la, 0, sizeof(la));
    la.sin_family = AF_INET;
    la.sin_addr.s_addr = INADDR_ANY;
    la.sin_port = htons(0);
	socklen_t lalen = sizeof(la);

    // bind
	if (bind(fd, (struct sockaddr*)&la, sizeof(la)) == -1) 
    perror("bind");

    // get local port
	if(-1 == getsockname(fd, (struct sockaddr*)&la, &lalen)) 
    perror("getsockname");
	printf("local port = %d\n", ntohs(la.sin_port));

    // OpenSSL
    SSL_library_init();

    SSL_CTX* ctx = NULL;
    ctx = SSL_CTX_new(DTLS_client_method());

	// set user custom info in dtls extension
	unsigned int ext_type = 323;
	char* add_arg = new char[128];
	memcpy(add_arg, "taiyi0323", 10);
	int result = SSL_CTX_add_client_custom_ext(ctx, ext_type, ext_add_cb, ext_free_cb, add_arg, NULL, NULL);
	if (result == 0) {
		std::cout << "SSL_CTX_add_client_custom_ext error" << std::endl;
		return -1;
	}
    
    assert(SSL_CTX_use_certificate_chain_file(ctx, "./myalirtc.com_SHA256withRSA_RSA.crt") == 1);
    assert(SSL_CTX_use_PrivateKey_file(ctx, "./myalirtc.com_SHA256withRSA_RSA.key", SSL_FILETYPE_PEM) == 1);
    SSL_CTX_set_default_verify_file(ctx);

    SSL* ssl = SSL_new(ctx);

    BIO* rbio = BIO_new(BIO_s_mem());
    BIO* wbio = BIO_new(BIO_s_mem());
    SSL_set_bio(ssl, rbio, wbio);

    BIO_reset(rbio);
    BIO_reset(wbio);

    // Dtls setup active, as client role.
    SSL_set_connect_state(ssl);

    int r0 = SSL_do_handshake(ssl);
    int r1 = SSL_get_error(ssl, r0);
    // Fatal SSL error, for example, no available suite when peer is DTLS 1.0 while we are DTLS 1.2.
    if (r0 < 0 && (r1 != SSL_ERROR_NONE && r1 != SSL_ERROR_WANT_READ && r1 != SSL_ERROR_WANT_WRITE)) {
        std::cout << "handshake r0=" << r0 << " r1=" << r1 << std::endl;
        exit(-1);
    }

    // send ClientHello
    char* data = NULL;
    int size = BIO_get_mem_data(wbio, &data);
    std::cout << "size=" << size << std::endl;
    struct sockaddr_in sa;
    socklen_t salen = sizeof(sa);
    memset(&sa, 0, salen);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr("127.0.0.1");
    sa.sin_port = htons(8000);
    size_t s = sendto(fd, data, size, 0, (struct sockaddr *)&sa, salen);
    printf("send msg: %s len: %d\n", data, s);

    // recv ServerHello...
    char rcvbuf[4096];
    struct sockaddr_in ra;
    socklen_t ralen = sizeof(ra);
    size_t r = recvfrom(fd, rcvbuf, 4096, 0, (struct sockaddr*)&ra, &ralen);
    printf("recv msg: %s len: %d ip: %s port: %d\n", rcvbuf, r, inet_ntoa(ra.sin_addr), ntohs(ra.sin_port));

    BIO_reset(rbio);
    BIO_reset(wbio);

    int ret = BIO_write(rbio, rcvbuf, r);

    r0 = SSL_do_handshake(ssl);
    r1 = SSL_get_error(ssl, r0);
    // Fatal SSL error, for example, no available suite when peer is DTLS 1.0 while we are DTLS 1.2.
    if (r0 < 0 && (r1 != SSL_ERROR_NONE && r1 != SSL_ERROR_WANT_READ && r1 != SSL_ERROR_WANT_WRITE)) {
        std::cout << "handshake r0=" << r0 << " r1=" << r1 << std::endl;
        exit(-1);
    }

    // send Client Key...
    data = NULL;
    size = BIO_get_mem_data(wbio, &data);
    std::cout << "size=" << size << std::endl;

    s = sendto(fd, data, size, 0, (struct sockaddr *)&sa, salen);
    printf("send msg: %s len: %d\n", data, s);

    // recv Change Cipher Spec...
    r = recvfrom(fd, rcvbuf, 4096, 0, (struct sockaddr*)&ra, &ralen);
    printf("recv msg: %s len: %d ip: %s port: %d\n", rcvbuf, r, inet_ntoa(ra.sin_addr), ntohs(ra.sin_port));

    BIO_reset(rbio);
    BIO_reset(wbio);

    ret = BIO_write(rbio, rcvbuf, r);

    r0 = SSL_do_handshake(ssl);
    r1 = SSL_get_error(ssl, r0);
    // Fatal SSL error, for example, no available suite when peer is DTLS 1.0 while we are DTLS 1.2.
    if (r0 < 0 && (r1 != SSL_ERROR_NONE && r1 != SSL_ERROR_WANT_READ && r1 != SSL_ERROR_WANT_WRITE)) {
        std::cout << "handshake r0=" << r0 << " r1=" << r1 << std::endl;
        exit(-1);
    }

    // OK, Handshake is done, note that it maybe done many times.
    if (r1 == SSL_ERROR_NONE) {
        handshake_done_for_us = true;
    }

    return 0;
}
