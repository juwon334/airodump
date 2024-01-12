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

struct ieee80211_header {
    uint16_t frame_control;
    uint16_t duration_id;
    uint8_t readdr1[6];
	uint8_t sourceaddr4[6];
	uint8_t bssid[6];
    uint16_t sequence_control;
    // addr4는 일부 프레임 유형에서만 사용됩니다.
};

// 비콘 프레임의 고정 필드
struct beacon_frame_fixed {
    uint64_t timestamp; // 타임스탬프
    uint16_t beacon_interval; // 비콘 인터벌
    uint16_t capabilities_info; // 캡 능력 정보
};

// 정보 요소 (가변 길이)
struct info_element {
    uint8_t id; // 정보 요소 ID
    uint8_t length; // 정보 요소 길이
    uint8_t data[]; // 정보 요소 데이터 (가변 길이)
};

// 전체 비콘 프레임
struct beacon_frame {
    struct ieee80211_header header; // 공통 헤더
    struct beacon_frame_fixed fixed; // 고정 필드
    struct info_element ie[]; // 정보 요소 (가변 길이 배열)
};

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
	int tsft;
	char binary[32];
	signed char antenna;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
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
		
		printf("%u bytes captured\n", header->caplen);
		printf("version : %d\n",rheader->it_version);
		printf("length : %d\n",rheader->it_len);
		binaryToIntArray(*present, binary);
		
		while(binary[0] == 1){
			present = (u_int32_t*)packet+offset;
			printf("present%d : 0x%2x\n",offset,*present);
			binaryToIntArray(*present, binary);
			if(binary[sizeof(binary)-1] == 1)
				tsft++;
			offset++;
		}

		offset *= 4;

		if(tsft != 0){
			offset += 8;
		}
		offset += 6;
		antenna = (signed char)packet[offset];
		printf("Antenna : %d\n",antenna);
		struct ieee80211_header *beacon = (struct ieee80211_header*)(packet+(rheader->it_len));
		printf("frame control : %2x\n",beacon->frame_control);
		printf("duration_id : %2x\n",beacon->duration_id);
		printf("readdr : ");
		print_addr(beacon->readdr1);
		printf("sourceaddr : ");
		print_addr(beacon->sourceaddr4);
		printf("bssid : ");
		print_addr(beacon->bssid);
		printf("sequ : %2x",beacon->sequence_control);
		printf("\n");
		printf("=====================================\n");
	}
	pcap_close(pcap);
	return 0;
}