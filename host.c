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

int is_valid_address(bdaddr_t current_address) {
  for (int i = 0; i < 6; i++) {
    if (current_address.b[i] != 0) {
      return 1;
    }
  }
  return 0;
}

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
  return rsa;
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
  printf("SELECTING\n");
  int select_result = select(sock + 1, &set, NULL, NULL, &timeout);
  int error = 0;
  socklen_t len = sizeof(error);
  getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len);
  printf("%d\n", error);
  if(select_result <= 0 || error) {
    close(sock);
    printf("Timed out\n");
    return -1;
  } else {
    read(sock, response, message_size);
  }
  if (memcmp(response, message, message_size)) {
    printf("1337 h4ck0r d3t3ct3d\n");
    close(sock);
    return -1;
  }
  return sock;
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

void lock_computer() {
  printf("Computer locked\n");
}

void start_client(RSA *rsa, int sock) {
  time_t end_time = time(NULL);
  sleep(INTERVAL);
  while (1) {
    printf("Challenging\n");
    time_t start_time = end_time;
    int result = challenge_device(rsa, sock);
    if (result < 0) {
      lock_computer();
      break;
    }
    end_time = time(NULL);
    time_t difference = end_time - start_time;
    sleep(INTERVAL - difference);
  }
}

int main() {
  char *target_name = "raspberrypi";
  RSA *rsa = get_public_key();
  int dev_id = hci_get_route(NULL);
  int sock = hci_open_dev(dev_id);
  int max_rsp = 255;
  int len = 8;
  int name_length = 248;
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
    if (!memcmp(name, target_name, strlen(target_name))) {
      printf("Device Found: Challenging It\n");
        int sock = connect_to_device(rsa, *current_address);
        if (sock >= 0) {
          start_client(rsa, sock);
          return 0;
        }
    }
    printf("%s:  '%s'\n", addr, name);
  }
}
