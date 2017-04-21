<<<<<<< HEAD
INC=/usr/local/ssl/include/
LIB=/usr/local/ssl/lib/

all:
	gcc -I$(INC) -L$(LIB) -o vpn simpletun1.c -lssl -lcrypto -ldl
	
clean:
	rm -rf *~ vpn
=======
obj-m += lkm1.o
obj-m += telnetfilter.o
obj-m += IPfilter.o
obj-m += icmppingin.o


all: 
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
>>>>>>> ae540a51e796bd9c937a44d5ecffab6f455e0bce
