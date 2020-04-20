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
#include "device.h"

int is_valid_address(bdaddr_t current_address) {
	for (int i = 0; i < 6; i++) {
		if (current_address.b[i] != 0) {
			return 1;
		}
	}
	return 0;
}

int connect_to_device(RSA *rsa, bdaddr_t current_address) {
	struct sockaddr_rc addr = { 0 };
	int sock = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
	// set the connection parameters (who to connect to)
	addr.rc_family = AF_BLUETOOTH;
	addr.rc_channel = (uint8_t) 1;
	addr.rc_bdaddr = current_address;
	if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("Could not connect");
		return -1;
	}
	return challenge_device(rsa, sock);
}

char *create_name(int argv, char **argc) {
	int size = (argv - 2);
	for (int i = 2; i < argv; i++) {
		size += strlen(argc[i]);
	}
	char *name = malloc(size);
	int pos = 0;
	for (int i = 2; i < argv; i++) {
		//strncpy not needed, assumed through strlen
		strcpy(name + pos, argc[i]);
		pos += strlen(argc[i]) + 1;
		name[pos - 1] = ' ';
	}
	name[size - 1] = 0;
	return name;
}

int main(int argv, char **argc) {
	if (argv <= 2) {
		printf("Invalid arguments\n");
		return 0;
	}
	char *target_name = create_name(argv, argc);
	if (!strncmp(argc[1], "0", 1)) {
		device_main(target_name);
		return 0;
	}
	RSA *rsa = get_public_key();
	int dev_id = hci_get_route(NULL);
	int sock = hci_open_dev(dev_id);
	int max_rsp = 255;
	int len = 8;
	int name_length = 248;
	while (1) {
		inquiry_info *inquiry_response = malloc(max_rsp * sizeof(inquiry_info));
		int num_rsp = hci_inquiry(dev_id, len, max_rsp, NULL, &inquiry_response, IREQ_CACHE_FLUSH);
		if (num_rsp < 0) {
			fprintf(stderr, "Bluetooth Not Turned On\n");
			exit(0);
		}
		char *addr = malloc(19);
		char *name = malloc(name_length);
		for (int i = 0; i < num_rsp; i++) {
			bdaddr_t *current_address = &(inquiry_response + i)->bdaddr;
			if (!is_valid_address(*current_address)) {
				continue;
			}
			ba2str(current_address, addr);
			memset(name, 0, (long unsigned int) name_length);
			hci_read_remote_name(sock, current_address, name_length, name, 0);
			printf("%s:  '%s'\n", addr, name);
			if (!memcmp(name, target_name, strlen(target_name))) {
				printf("Device Found: Challenging It\n");
					int sock = connect_to_device(rsa, *current_address);
					if (sock >= 0) {
						start_client(rsa, sock);
						return 0;
					}
			}
		}
	}
}
