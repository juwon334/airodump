#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <arpa/inet.h>

struct ieee80211_radiotap_header {
	u_int8_t        it_version;     /* set to 0 */
	u_int8_t        it_pad;
	u_int16_t       it_len;         /* entire length */
	u_int32_t       it_present;     /* fields present */
} __attribute__((__packed__));

struct present
{
	u_int32_t present;
};


void usage() {
	printf("syntax: ./ad <interface>\n");
	printf("sample: ./ad wlan0\n");
}
void printBinary(unsigned int num) {
	unsigned int mask = 1 << (sizeof(num) * 8 - 1);

	for (int i = 0; i < sizeof(num) * 8; i++) {
		printf("%d", (num & mask) ? 1 : 0);
		mask >>= 1;
	}
	printf("\n");
}


void binaryToIntArray(unsigned int num, int *arr) {
    unsigned int mask = 1 << (sizeof(num) * 8 - 1);

    for (int i = 0; i < sizeof(num) * 8; i++) {
        arr[i] = (num & mask) ? 1 : 0;
        mask >>= 1;
    }
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;
	
	int binary[32];

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		struct ieee80211_radiotap_header *rheader = (struct ieee80211_radiotap_header*)packet;
		struct present *rpresent = (struct present*)packet+1;
		int x = packet[rheader->it_len];
		if(x != 0x80)
			continue;
		printf("%u bytes captured\n", header->caplen);
		printf("version : %d\n",rheader->it_version);
		printf("length : %d\n",rheader->it_len);
		printf("present1 : 0x%2x\n",rpresent->present);
		binaryToIntArray(rpresent->present, binary);
		int j = 2;
		while(binary[0] == 1){
			u_int32_t *k = (u_int32_t*)packet+j;
			printf("present%d : 0x%2x\n",j-1,*k);
			binaryToIntArray(*k, binary);
			j++;
		}
		printf("=====================================\n");
	}
	pcap_close(pcap);
	return 0;
}