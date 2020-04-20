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


#include "challenge.h"

void write_public_key(char *public_key, int length) {
	FILE *f = fopen("public_key.der", "wb");
	for (int i = 0; i < length; i++) {
		fprintf(f, "%c", public_key[i]);
	}
	fclose(f);
	system("openssl rsa -pubin -in public_key.der -inform DER -outform PEM -out public_key.pem; rm public_key.der");
}

int is_device(int sock, struct sockaddr_rc remote_addr, char *target_name) {
	char *response = malloc(248);
	fd_set set;
	FD_ZERO(&set);
	FD_SET(sock, &set);
	struct timeval timeout;
	timeout.tv_sec = INTERVAL;
	timeout.tv_usec = 0;
	int select_result = select(sock + 1, &set, NULL, NULL, &timeout);
	int error = 0;
	socklen_t len = sizeof(error);
	getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len);
	if(select_result <= 0 || error) {
		close(sock);
		printf("Timed out\n");
		return -1;
	}
	read(sock, response, 248);
	char *ret = malloc(1);
	if (strncmp(response, target_name, strlen(target_name))) {
		ret[0] = 0;
		printf("Wrong name '%s':'%s'\n", response, target_name);
		write(sock, ret, 1);
		return -1;
	}
	printf("Device found\n");
	ret[0] = 1;
	write(sock, ret, 1);
	return 0;
}

int has_public_key() {
	return access("public_key.pem", F_OK ) != -1;
}

void create_keys(int sock) {
	char *message = malloc(1);
	message[0] = 1;
	write(sock, message, 1);
	char *length_string = malloc(2);
	read(sock, length_string, 2);
	int length = length_string[0] * 256 + length_string[1];
	char *public_key = malloc(length + 1);
	read(sock, public_key, length);
	public_key[length] = 0;
	write_public_key(public_key, length);
}

void device_main(char *target_name) {
	struct sockaddr_rc local_addr, remote_addr;
	socklen_t opt = sizeof(remote_addr);
	int sock = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
	local_addr.rc_family = AF_BLUETOOTH;
	local_addr.rc_bdaddr = *BDADDR_ANY;
	local_addr.rc_channel = (uint8_t) 1;
	bind(sock, (struct sockaddr *) &local_addr, sizeof(local_addr));
	listen(sock, 1);
	while (1) {
		int client_sock = accept(sock, (struct sockaddr *) &remote_addr, &opt);
		if (is_device(client_sock, remote_addr, target_name) < 0) {
			close(client_sock);
			continue;
		}
		if (!has_public_key()) {
			create_keys(client_sock);
		} else {
			char *message = malloc(1);
			message[0] = 0;
			write(client_sock, message, 1);
		}
		RSA *rsa = get_pem_public_key();
		start_client(rsa, client_sock);
		close(client_sock);
	}
	close(sock);
	return;
}
