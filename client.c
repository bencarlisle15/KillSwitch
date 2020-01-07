#include <stdio.h>
#include <unistd.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>

RSA *get_private_key() {
  FILE *f = fopen("private_key","rb");
  RSA *rsa= RSA_new();
  rsa = PEM_read_RSAPrivateKey(f, &rsa, NULL, NULL);
  fclose(f);
  return rsa;
}

char *decrypt_challenge(RSA *rsa, unsigned char *challenge) {
    int ciphertext_size = RSA_size(rsa);
    unsigned char *message = malloc(ciphertext_size - 42);
    RSA_private_decrypt(ciphertext_size, challenge, message, rsa, RSA_PKCS1_OAEP_PADDING);
    return message;
}

int main(int argc, char **argv) {
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
	if (fork()) {
	    continue;
	}
	while (1) {
		RSA *rsa = get_private_key();
		int ciphertext_size = RSA_size(rsa);
		int message_size = ciphertext_size - 42;
		char *challenge = malloc(ciphertext_size);
		fd_set set;
  		FD_ZERO(&set);
  		FD_SET(client_sock, &set);
  		struct timeval timeout;
  		timeout.tv_sec = 60;
  		timeout.tv_usec = 0;
  		int select_result = select(client_sock + 1, &set, NULL, NULL, &timeout);
		int error = 0;
		socklen_t len = sizeof(error);
		getsockopt(client_sock, SOL_SOCKET, SO_ERROR, &error, &len);
		if(select_result <= 0 || error) {
  			printf("Timed out\n");
  			break;
  		} else {
			read(client_sock, challenge, ciphertext_size);
		}
		printf("New message received\n");
		unsigned char *message = decrypt_challenge(rsa, challenge);
		write(client_sock, message, message_size);
		free(message);
		free(challenge);
		printf("Message sent\n");
	}
	close(client_sock);
	return 0;
    }
    close(sock);
    return 0;
}
