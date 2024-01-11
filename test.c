#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAXBYTES2CAPTURE 2048

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    const u_char *ssid;
    int ssid_length;
    int offset = 38; // Beacon 패킷의 SSID 위치에 대한 오프셋

    // Beacon 프레임 (Type/Subtype: 0x0080) 검사
    if (packet[0] == 0x80) {
        ssid_length = packet[offset];
        ssid = packet + offset + 1;
        printf("SSID: ");
        for (int i = 0; i < ssid_length; i++) {
            putchar(ssid[i]);
        }
        printf("\n");
    }
}

int main() {
    pcap_t *descr = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    memset(errbuf, 0, PCAP_ERRBUF_SIZE);

    // 사용할 장치 이름 지정 (예: "wlan0")
    char *device = "wlx588694fa3d0e";

    // 장치 열기
    descr = pcap_open_live(device, MAXBYTES2CAPTURE, 1, 512, errbuf);
    if (descr == NULL) {
        printf("pcap_open_live() 실패: %s\n", errbuf);
        return -1;
    }

    // 패킷 캡처 시작
    if (pcap_loop(descr, -1, packetHandler, NULL) < 0) {
        fprintf(stderr, "\npcap_loop() 실패: %s\n", pcap_geterr(descr));
        return -1;
    }

    // 종료
    pcap_close(descr);
    return 0;
}
