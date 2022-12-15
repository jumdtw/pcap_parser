#include<pcap/pcap.h>
#include<iostream>
#include<fstream>

pcap_t *my_pcap_create(const char *read_pcap_path){
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    //const char *pcap_path = argv[1];
    // read pcapfile
    pcap_t *pcap = pcap_open_offline_with_tstamp_precision(read_pcap_path, PCAP_TSTAMP_PRECISION_NANO, pcap_errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open: error %s\n", pcap_errbuf);
        exit(EXIT_FAILURE);
    }
    return pcap;
}

pcap_dumper_t *my_create_pcap_dumper(const char *save_pcap_path){
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *save_pcap = pcap_create("any", pcap_errbuf);
    if((pcap_activate(save_pcap))!=0){
        fprintf(stderr, "pcap_t create: error %s\n", pcap_geterr(save_pcap));
        exit(EXIT_FAILURE);
    }
    pcap_dumper_t *dumper = pcap_dump_open(save_pcap, save_pcap_path);
    if (dumper == NULL) {
        fprintf(stderr, "pcap_dump_open: error %s\n", pcap_geterr(save_pcap));
        exit(EXIT_FAILURE);
    }
    return dumper;
}

int main(int argc, char *argv[]){
    const u_char *pkt;

    // read pcapfile
    pcap_t *pcap = my_pcap_create(argv[1]);

    //create dumper
    pcap_dumper_t *dumper = my_create_pcap_dumper(argv[2]);

    struct pcap_pkthdr pkthdr;
    while ((pkt = pcap_next(pcap, &pkthdr))) {
        pcap_dump((u_char *)dumper, &pkthdr, pkt);
    }
    pcap_dump_flush(dumper);
    pcap_dump_close(dumper);
    pcap_close(pcap);


    std::ifstream ifout(argv[2], std::ios::binary);
    std::ofstream ofout(argv[3], std::ios::binary);
    double d;
    ifout.seekg(0, std::ios::end);
    long long int size = ifout.tellg();
    ifout.seekg(0);
    //unsigned int a = 0x114;
    if(!ifout){
        std::cout << "ifout open error";
        return 1;
    }
        if(!ofout){
        std::cout << "ofout open error";
        return 1;
    }
    for (long long int i=0;i<size;i++){
        ifout.read((char *)&d, sizeof(char));
        ofout.write((char *)&d, sizeof(char));
    }
    ifout.close();
    ofout.close();

}
