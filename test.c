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
	u_int32_t       it_present;     /* fields present */
} __attribute__((__packed__));

struct ieee80211_header {
	uint16_t frame_control;
	uint16_t duration_id;
	uint8_t readdr1[6];
	uint8_t sourceaddr4[6];
	uint8_t bssid[6];
	uint16_t sequence_control;
};

// 비콘 프레임의 고정 필드
struct beacon_frame_fixed {
	uint8_t timestamp[8];
	uint8_t beacon_interval[2]; 
	uint8_t capabilities_info[2];
};

// 정보 요소 (가변 길이)
struct info_element {
	uint8_t id;
	uint8_t length;
	uint8_t data[];
};

// 전체 비콘 프레임
struct beacon_frame {
	struct ieee80211_header header;
	struct beacon_frame_fixed fixed;
	struct info_element ie[];
};

struct present
{
	u_int32_t present;
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
typedef struct ssid_count {
	char ssid[33];
	int count;
	struct ssid_count *next;
} ssid_count_t;

ssid_count_t *head = NULL;

ssid_count_t *find_or_create_ssid(const char *ssid) {
	ssid_count_t *current = head;
	while (current != NULL) {
		if (strcmp(current->ssid, ssid) == 0) {
			return current;
		}
		current = current->next;
	}

	// 새로운 SSID 항목 생성
	ssid_count_t *new_node = (ssid_count_t *)malloc(sizeof(ssid_count_t));
	if (new_node == NULL) {
		fprintf(stderr, "Memory allocation failed.\n");
		exit(EXIT_FAILURE);
	}
	strncpy(new_node->ssid, ssid, 32);
	new_node->ssid[32] = '\0'; // 널 종료 문자 보장
	new_node->count = 0;
	new_node->next = head;
	head = new_node;
	return new_node;
}
void increment_and_print_ssid_count(const char *ssid) {
	ssid_count_t *ssid_node = find_or_create_ssid(ssid);
	ssid_node->count++;
	printf("SSID : %s\nbeacons : %d\n", ssid, ssid_node->count);
}

// 메모리 정리 함수
void cleanup() {
	ssid_count_t *current = head;
	while (current != NULL) {
		ssid_count_t *temp = current;
		current = current->next;
		free(temp);
	}
}

void print_info_elements(const u_char* packet, int offset, size_t packet_len) {
	while (offset < packet_len) {
		struct info_element* ie = (struct info_element*)(packet + offset);

		if (ie->id == 3 && ie->length == 1) {
			printf("Channel: %d\n", ie->data[0]);
		}

		if (ie->id == 0) { // SSID 정보 요소
			char *ssid = uint8ArrayToAsciiString(ie->data, ie->length);
			if (ssid != NULL) {
				increment_and_print_ssid_count(ssid); // SSID 카운트 증가 및 출력
				free(ssid);
			} else {
				printf("Memory allocation failed for SSID.\n");
			}
		}
		offset += 2 + ie->length;
	}
}

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

void binaryToIntArray(unsigned int num, char *arr) {
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
void print_addr(u_int8_t *m){
	printf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
	printf("\n");
}


int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;
	int offset;
	size_t size;
	int tsft;
	char binary[32];
	signed char antenna;
	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_offline(argv[1], errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_offline(%s) return null - %s\n", argv[1], errbuf);
        return -1;
    }

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		tsft = 0;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;

		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		struct ieee80211_radiotap_header *rheader = (struct ieee80211_radiotap_header*)packet;
		int x = packet[rheader->it_len];
		offset = 1;

		u_int32_t *present = (u_int32_t*)packet+offset;

		if(x != 0x80)
			continue;
		binaryToIntArray(*present, binary);
		while(binary[0] == 1){
			present = (u_int32_t*)packet+offset;
			binaryToIntArray(*present, binary);
			if(binary[sizeof(binary)-1] == 1)
				//mactime
				tsft++;
			offset++;
		}
		if(binary[0] != 1)
			offset++;
		
		offset *= 4;

		if(tsft != 0){
			offset += 8;
		}
		offset += 6;

		antenna = (signed char)packet[offset];
		printf("test : %2x\n",packet[offset]);
		printf("Pwr : %d\n",antenna);
		struct beacon_frame *beacon = (struct beacon_frame*)(packet+(rheader->it_len));
		printf("bssid : ");
		print_addr(beacon->header.bssid);
		int beacon_frame_offset = rheader->it_len + sizeof(struct ieee80211_header) + sizeof(struct beacon_frame_fixed);
		print_info_elements(packet, beacon_frame_offset, header->caplen);
		printf("=====================================\n");
	}
	cleanup();
	pcap_close(pcap);
	return 0;
}
