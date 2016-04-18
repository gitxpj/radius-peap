
all:
	gcc -c src/radiuspkg.c src/eap.c -std=gnu99
	ar -crv ../libs/libradiuspkg.a eap.o radiuspkg.o
