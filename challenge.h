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

char *read_all_lines(FILE *f);
RSA *get_public_key();
RSA *get_pem_public_key();
int challenge_device(RSA *rsa, int sock);
void lock_computer();
void start_client(RSA *rsa, int sock);
