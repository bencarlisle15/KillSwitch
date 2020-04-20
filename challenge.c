#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/hci_lib.h>

#define INTERVAL 5

char *read_all_lines(FILE *f) {
	char *buffer = malloc(0);
	char *current_line = calloc(1024, sizeof(char));
	int total_size = 0;
	while (fgets(current_line, 1024, f) != NULL) {
			int line_size = strlen(current_line);
			buffer = realloc(buffer, total_size + line_size);
			memcpy(buffer + total_size, current_line, line_size);
			total_size += line_size;
	}
	free(current_line);
	buffer = realloc(buffer, total_size + 1);
	buffer[total_size] = 0;
	return buffer;
}

RSA *get_public_key() {
	FILE *f = fopen("public_key", "rb");
	char *pub_key_pem = read_all_lines(f);
	BIO *bio = BIO_new_mem_buf((void*) pub_key_pem, strlen(pub_key_pem));
	RSA *rsa = PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL);
	fclose(f);
	if (!rsa) {
		printf("Invalid key\n");
		exit(0);
	}
	return rsa;
}

RSA *get_pem_public_key() {
	FILE *f  = fopen("public_key.pem", "rb");
	RSA *rsa= RSA_new();
	return PEM_read_RSA_PUBKEY(f, &rsa, NULL, NULL);
}

int challenge_device(RSA *rsa, int sock) {
	int ciphertext_size = RSA_size(rsa);
	int message_size = ciphertext_size - 42;
	unsigned char *message = calloc(message_size, sizeof(char));
	RAND_bytes(message, message_size);
	unsigned char *challenge = malloc(ciphertext_size);
	int result = RSA_public_encrypt(message_size, message, challenge, rsa, RSA_PKCS1_OAEP_PADDING);
	unsigned char *response = malloc(message_size);
	write(sock, challenge, ciphertext_size);
	fd_set set;
	FD_ZERO(&set);
	FD_SET(sock, &set);
	struct timeval timeout;
	timeout.tv_sec = INTERVAL;
	timeout.tv_usec = 0;
	printf("Select start\n");
	int select_result = select(sock + 1, &set, NULL, NULL, &timeout);
	int error = 0;
	socklen_t len = sizeof(error);
	getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len);
	if(select_result <= 0 || error) {
		close(sock);
		printf("Timed out\n");
		return -1;
	} else {
		printf("Read start\n");
		read(sock, response, message_size);
		printf("Read end\n");
	}
	if (memcmp(response, message, message_size)) {
		printf("1337 h4ck0r d3t3ct3d\n");
		close(sock);
		return -1;
	}
	return sock;
}

void lock_computer() {
	printf("Computer locked\n");
	// system("physlock");
}

void start_client(RSA *rsa, int sock) {
	time_t end_time = time(NULL);
	sleep(INTERVAL);
	while (1) {
		printf("Challenging\n");
		time_t start_time = time(NULL);
		int result = challenge_device(rsa, sock);
		if (result < 0) {
			lock_computer();
			break;
		}
		end_time = time(NULL);
		time_t difference = end_time - start_time;
		int sleep_time = INTERVAL - difference;
		if (sleep_time < 0) {
			sleep_time = 0;
		}
		sleep(sleep_time);
	}
}
