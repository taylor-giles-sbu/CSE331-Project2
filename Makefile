CC=gcc
CFLAGS=-g -Wall -m32 -DGRP=$(GRP_ID) -DLEN1=1021 -DLEN2=256 -DLEN3=256 -DRANDOM=0
#CFLAGS=-g -Wall -DLEN1=1021 -DLEN2=256 -DLEN3=1000 -DRANDOM=random\(\)

all: vuln.s vuln driver driver_authd_expl

vuln: vuln.o my_malloc.o
	$(CC) $(CFLAGS) -o vuln vuln.o my_malloc.o
	execstack -s vuln

vuln.o: padding.h vuln.c my_malloc.h
	$(CC) $(CFLAGS) -c vuln.c

vuln.s: vuln.c my_malloc.h
	$(CC) $(CFLAGS) -DASM_ONLY -c -g -Wa,-a,-ad vuln.c > vuln.s
	rm vuln.o

my_malloc.o: my_malloc.h my_malloc.c
	$(CC) $(CFLAGS)  -c my_malloc.c

driver: driver.c
	$(CC) $(CFLAGS) -o driver driver.c

driver_authd_expl: driver_authd_expl.c
	$(CC) $(CFLAGS) -o driver_authd_expl driver_authd_expl.c

padding.h:
	./mkpad $(GRP_ID)

clean:
	rm -f vuln vuln.o my_malloc.o vuln.s padding.h driver_authd_expl driver
