all: host client

client:
	gcc client.c -o client -lbluetooth -lcrypto

host:
	gcc host.c -o host -lbluetooth -lcrypto
