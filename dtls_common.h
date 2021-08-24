#include <openssl/ssl.h>

#include "buffer.h"

static int ext_add_cb(SSL* s, unsigned int ext_type, 
		const unsigned char** out, size_t* outlen, int* al, void* add_arg)
{
	printf("ext_add_cb called\n");

	switch (ext_type) {
		case 323:
		{
			printf("add_arg: %s, arglen: %d\n", add_arg, *al);
			int len = strlen((const char*)add_arg);
			unsigned char* p = (unsigned char*)malloc(len);
			memcpy(p, add_arg, len);
			*out = p;
			*outlen = len;
			break;
		}

		default:
			break;
	}

	return 1;
}

static void ext_free_cb(SSL* s, unsigned int ext_type,
		const unsigned char* out, void* add_arg)
{
	printf("ext_free_cb called\n");

	if (add_arg) {
		free(add_arg);
	}
}

static int ext_parse_cb(SSL* s, unsigned int ext_type,
		const unsigned char* in,
		size_t inlen, int* al, void* parse_arg)
{
	printf("ext_parse_cb called\n");

	memcpy(parse_arg, in, inlen);
	std::cout << "API 解析custom ext: userinfo=" << (unsigned char*)parse_arg << std::endl;

	return 1;
}

int parse_client_hello_custom_ext(char* data, size_t size, std::string& user_info)
{
    SrsBuffer client_hello(data, size);

    int skip = 1   // content type
             + 2   // version
             + 2   // epoch
             + 6   // sequence number
             + 2   // length
             + 1   // handshake type
             + 3   // length
             + 2   // message sequence
             + 3   // fragment offset
             + 3   // fragment length
             + 2   // version
             + 32; // random

    int require = skip
             + 1   // session id length
             + 1   // cookie id length
             + 2   // cipher suites length
             + 1   // compression methods length
             + 2;  // extensions length

    if (! client_hello.require(require)) {
		return -1;
    }
    client_hello.skip(skip);

    int session_id_len = client_hello.read_1bytes();
    if (! client_hello.require(session_id_len)) {
		return -1;
    }
    client_hello.skip(session_id_len);

    int cookie_len = client_hello.read_1bytes();
    if (! client_hello.require(cookie_len)) {
		return -1;
    }
    client_hello.skip(cookie_len);

    int cipher_suites_len = client_hello.read_2bytes();
    if (! client_hello.require(cipher_suites_len)) {
		return -1;
    }
    client_hello.skip(cipher_suites_len);

    int compression_methods_len = client_hello.read_1bytes();
    if (! client_hello.require(compression_methods_len)) {
		return -1;
    }
    client_hello.skip(compression_methods_len);

    int extensions_len = client_hello.read_2bytes();
    int left_len = client_hello.left();
    if (extensions_len != left_len) {
		return -1;
    }

    // just parse custom extension.
    while (client_hello.left() > 0) {
        int extension_type = client_hello.read_2bytes();
        if (323 == extension_type) {
            user_info = client_hello.read_string(client_hello.read_2bytes());
            return 0;
        }
    }

	return -1;
}
