LDLIBS += -lpcap

all: ad

all: test

airodump_on: ad.c

airodump_off: test.c

clean:
	rm -f ad *.o
	rm -f test *.o
