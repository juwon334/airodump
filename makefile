LDLIBS += -lpcap

all: ad

pcap-test: ad.c

clean:
	rm -f ad *.o