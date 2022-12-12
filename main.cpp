#include<pcap.h>
#include<iostream>

int main(int argc, char *argv[]){
    const u_char *pkt;
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    const char *pcap_path = argv[1];

    pcap_t *pcap = pcap_open_offline_with_tstamp_precision(pcap_path, PCAP_TSTAMP_PRECISION_NANO, pcap_errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open: error %s\n", pcap_errbuf);
        exit(EXIT_FAILURE);
    }

    struct pcap_pkthdr pkthdr;
    while ((pkt = pcap_next(pcap, &pkthdr))) {
        std::cout << pkthdr.len << "\n";
    }
    pcap_close(pcap);
}
