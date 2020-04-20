all: host client

client:
	gcc client.c -o client -lbluetooth -lcrypto

host:
	gcc host.c device.c challenge.c -o host -lbluetooth -lcrypto

clean:
	rm host client

full:	clean all
