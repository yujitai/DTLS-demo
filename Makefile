#author@yujitai

all: dtls_server dtls_client

dtls_server : dtls_server.cpp
	g++ dtls_server.cpp -I./openssl/include ./openssl/lib/libssl.a ./openssl/lib/libcrypto.a -o dtls_server -g

dtls_client : dtls_client.cpp
	g++ dtls_client.cpp -I./openssl/include ./openssl/lib/libssl.a ./openssl/lib/libcrypto.a -o dtls_client -g

.PHONY : clean
clean :
	rm dtls_server
	rm dtls_client

