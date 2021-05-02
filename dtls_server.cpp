#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>

#include <thread>

#include <iostream>

// TODO: 支持切片发送

int fd = -1;
size_t nread = -1;
char recv_buf[1500] = {0};
struct sockaddr_in cli_addr;
socklen_t cli_addr_len = sizeof(cli_addr);
char* data = NULL;

SSL_CTX* ctx = NULL;
SSL* ssl     = NULL;
BIO* rbio    = NULL;
BIO* wbio    = NULL;

int listen_udp()
{
    // create udp socket
    fd = socket(AF_INET, SOCK_DGRAM, 0);

    // local address
    struct sockaddr_in la;
    memset(&la, 0, sizeof(la));
    la.sin_family = AF_INET;
    la.sin_addr.s_addr = INADDR_ANY;
    la.sin_port = htons(8000);
	socklen_t lalen = sizeof(la);

    // bind
	if (-1 == bind(fd, (struct sockaddr*)&la, sizeof(la))) {
        perror("bind");
        return -1;
    }

    // get local port
	if(-1 == getsockname(fd, (struct sockaddr*)&la, &lalen)) {
        perror("getsockname");
        return -1;
    }

    std::cout << "dtls server listen: 127.0.0.1:8000" << std::endl;

    return 0;
}

int init_OpenSSL()
{
    SSL_library_init();

    ctx = SSL_CTX_new(DTLS_server_method());

    assert(SSL_CTX_use_certificate_chain_file(ctx, "./myalirtc.com_SHA256withRSA_RSA.crt") == 1);
    assert(SSL_CTX_use_PrivateKey_file(ctx, "./myalirtc.com_SHA256withRSA_RSA.key", SSL_FILETYPE_PEM) == 1);
    SSL_CTX_set_default_verify_file(ctx);

    ssl = SSL_new(ctx);

    rbio = BIO_new(BIO_s_mem());
    wbio = BIO_new(BIO_s_mem());
    SSL_set_bio(ssl, rbio, wbio);

    // Dtls setup passive, as server role.
    SSL_set_accept_state(ssl);
}

int recv_DTLS_message()
{
    nread = recvfrom(fd, recv_buf, 1500, 0, (struct sockaddr*)&cli_addr, &cli_addr_len);
    // TODO: parse DTLS Message type.
    printf("recv DTLS message: %s len: %d ip: %s port: %d\n", recv_buf, nread, inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port));
}

int do_DTLS_handshake()
{
    // Why must reset?
    BIO_reset(rbio);
    BIO_reset(wbio);
    BIO_write(rbio, recv_buf, nread);

    int r0 = SSL_do_handshake(ssl);
    int r1 = SSL_get_error(ssl, r0);
    // Fatal SSL error, for example, no available suite when peer is DTLS 1.0 while we are DTLS 1.2.
    if (r0 < 0 && (r1 != SSL_ERROR_NONE && r1 != SSL_ERROR_WANT_READ && r1 != SSL_ERROR_WANT_WRITE)) {
        std::cout << "handshake r0=" << r0 << " r1=" << r1 << std::endl;
        exit(-1);
    }
}

int send_DTLS_message()
{ 
    int size = BIO_get_mem_data(wbio, &data);
    std::cout << "size=" << size << std::endl;
    size_t nwrite = sendto(fd, data, size, 0, (struct sockaddr *)&cli_addr, cli_addr_len);
    printf("send msg: %s len: %d\n", data, nwrite);
}

int main(int ac, const char *av[])
{
    listen_udp();

    init_OpenSSL();

    recv_DTLS_message();
    do_DTLS_handshake();
    send_DTLS_message();

    recv_DTLS_message();
    do_DTLS_handshake();
    send_DTLS_message();

    return 0;
}

