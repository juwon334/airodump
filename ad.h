#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>

struct ieee80211_radiotap_header {
	u_int8_t        it_version;     /* set to 0 */
	u_int8_t        it_pad;
	u_int16_t       it_len;         /* entire length */
} __attribute__((__packed__));

struct nextpresent{
	uint8_t flag;
	uint8_t datarate;
	uint16_t cf;
	uint16_t cflag;
	uint8_t pwr;
};

struct ieee80211_header {
	uint16_t frame_control;
	uint16_t duration_id;
	uint8_t readdr1[6];
	uint8_t sourceaddr4[6];
	uint8_t bssid[6];
	uint16_t sequence_control;
};

struct beacon_frame_fixed {
	uint8_t timestamp[8];
	uint8_t beacon_interval[2]; 
	uint8_t capabilities_info[2];
};

struct info_element {
	uint8_t id;
	uint8_t length;
	uint8_t data[];
};

struct beacon_frame {
	struct ieee80211_header header;
	struct beacon_frame_fixed fixed;
	struct info_element ie[];
};

struct tag_rsn{
    uint8_t rsnid;
	uint8_t rsnlength;
	uint16_t version;
    uint32_t GroupCipherss;
    uint16_t pairwisesc;
};

char* uint8ArrayToAsciiString(const uint8_t *array, size_t size) {
	char *asciiString = malloc(size + 1); // +1 for null-terminator
	if (asciiString == NULL) {
		return NULL;
	}
	for (size_t i = 0; i < size; ++i) {
		asciiString[i] = (char)array[i];
	}
	asciiString[size] = '\0';
	return asciiString;
}

void printBinary(unsigned int num) {
	unsigned int mask = 1 << (sizeof(num) * 8 - 1);

	for (int i = 0; i < sizeof(num) * 8; i++) {
		printf("%d", (num & mask) ? 1 : 0);
		mask >>= 1;
	}
	printf("\n");
}

void binaryToIntArray(unsigned int num, char *arr) {
	unsigned int mask = 1 << (sizeof(num) * 8 - 1);
	for (int i = 0; i < sizeof(num) * 8; i++) {
		arr[i] = (num & mask) ? 1 : 0;
		mask >>= 1;
	}
}

void print_addr(u_int8_t *m){
	printf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
	printf("\n");
}