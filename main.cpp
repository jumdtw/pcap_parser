#include<pcap.h>
#include<iostream>

int main(int argc, char *argv[]){
    const u_char *pkt;
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    const char *pcap_path = argv[1];

    // read pcapfile
    pcap_t *pcap = pcap_open_offline_with_tstamp_precision(pcap_path, PCAP_TSTAMP_PRECISION_NANO, pcap_errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open: error %s\n", pcap_errbuf);
        exit(EXIT_FAILURE);
    }

    //create dumper
    pcap_t *save_pcap = pcap_create(NULL, pcap_errbuf);
    if((pcap_activate(save_pcap))!=0){
        fprintf(stderr, "pcap_t create: error %s\n", pcap_geterr(save_pcap));
        exit(EXIT_FAILURE);
    }
    pcap_dumper_t *dumper = pcap_dump_open(save_pcap, "./gen_test.pcap");
    if (dumper == NULL) {
        fprintf(stderr, "pcap_dump_open: error %s\n", pcap_geterr(save_pcap));
        exit(EXIT_FAILURE);
    }


    struct pcap_pkthdr pkthdr;
    while ((pkt = pcap_next(pcap, &pkthdr))) {
        std::cout << pkthdr.len << "\n";
        pcap_dump((u_char *)dumper, &pkthdr, pkt);
    }


    pcap_dump_flush(dumper);
    pcap_dump_close(dumper);
    pcap_close(pcap);
}
