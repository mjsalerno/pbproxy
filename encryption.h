#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <openssl/aes.h>
#include <openssl/rand.h> 
#include <openssl/hmac.h>
#include <openssl/buffer.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <unistd.h>

struct ctr_state { 
	unsigned char ivec[AES_BLOCK_SIZE];	 
	unsigned int num; 
	unsigned char ecount[AES_BLOCK_SIZE]; 
};

void init_out(const unsigned char *enc_key);
void fencrypt(void *dest, const void *src, size_t n);
void send_iv(int fd);
void init_in(const unsigned char *enc_key, const unsigned char iv[16]);
void fdecrypt(void *dest, const void *src, size_t n);

#endif