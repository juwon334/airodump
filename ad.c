#include "ad.h"

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
		
		if(ie->id == 48){
			int of = 1;
			int auth;
			struct info_element* rsn = (struct info_element*)(packet+offset);
			uint16_t *psuiteCount = (uint16_t*)(rsn->data+6);
			int *cipher = malloc(*psuiteCount * sizeof(int));
			for(int i = 0;i<*psuiteCount;i++){
				uint8_t *psu = (uint8_t*)(rsn->data+6+1+of+(i*4));
				switch(psu[3]){
					case 0 : 
					printf("CIPHER : USE GROUP CIPHER SUITE\n");
					cipher[i] = 0;
					break;
				case 1 :
					printf("CIPHER : WEP-40\n");
					cipher[i] = 1;
					break;
				case 2 :
					printf("CIPHER : TKIP\n");
					cipher[i] = 2;
					break;
				case 3 :
					printf("CIPHER : RESERVATION\n");
					cipher[i] = 3;
					break;
				case 4 :
					printf("CIPHER : CCMP\n");
					cipher[i] = 4;
					break;
				case 5 :
					printf("CIPHER : WEP-104\n");
					cipher[i] = 5;
					break;
				}
			}
			of *= (*psuiteCount);
			of *= 4;
			uint16_t *akmsuitCount = (uint16_t*)(rsn->data+6+of+sizeof(*psuiteCount));
			for(int i = 0;i<*akmsuitCount;i++){
				uint8_t *akm = (uint8_t*)(rsn->data+6+2+of+sizeof(*psuiteCount));
				switch(akm[3]){
					case 0 : 
						printf("AUTH : Reservation\n");
						auth = 0;
						break;
					case 1 :
						printf("AUTH : 802.1x\n");
						auth = 1;
						break;
					case 2 :
						printf("AUTH : PSK\n");
						auth = 2;
						break;
					default :
						printf("AUTH : VENDOR..\n");
						auth = 3;
						break;
				}
			}
			
			for(int i =0;i<sizeof(cipher);i++){
				if(cipher[i] == 4 && auth == 2){
					printf("ENC : WPA2\n");
					break;
				}
					
				else if(cipher[i] == 2 && auth == 2){
					printf("ENC : WAP\n");
				}
			}
		}
		offset += 2 + ie->length;
	}
}

void usage() {
	printf("syntax: ./ad <interface>\n");
	printf("sample: ./ad wlan0\n");
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
	int offset;
	size_t size;
	int tsft;
	u_int32_t *present;
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
		offset = 0;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;

		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		struct ieee80211_radiotap_header *rheader = (struct ieee80211_radiotap_header*)packet;
		int x = packet[rheader->it_len];

		if(x != 0x80)
			continue;

		while(1){
			present = (u_int32_t*)(packet+sizeof(*rheader)+offset);
			binaryToIntArray(*present, binary);
			if(binary[0] == 1){
				if(binary[sizeof(binary)-1] == 1){
					tsft++;
				}
				offset+=4;
				continue;
			}
			else if(binary[0]!=1){
				if(binary[sizeof(binary)-1] == 1){
					tsft++;
				}
				offset+=4;
				break;
			}
		}

		if(tsft != 0){
			offset+=8;
		}

		struct nextpresent *np = (struct nextpresent*)(packet+sizeof(*rheader)+offset);
		printf("pwr : %d\n",(signed char)np->pwr);

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