#include<pcap/pcap.h>
#include<iostream>
#include<fstream>
#include<string.h>
#include"main.hpp"

int check_link_type(pcap_t *pcap){
    int a =pcap_datalink(pcap);
    if(a!=0x114){
        fprintf(stderr, "File check.link type %d\n", a);
        return 1;
    }
    return 0;
}

pcap_t *my_pcap_read(const char *read_pcap_path){
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    //const char *pcap_path = argv[1];
    // read pcapfile
    pcap_t *pcap = pcap_open_offline_with_tstamp_precision(read_pcap_path, PCAP_TSTAMP_PRECISION_NANO, pcap_errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open: error %s\n", pcap_errbuf);
        exit(EXIT_FAILURE);
    }
    if(check_link_type(pcap)){exit(EXIT_FAILURE);};
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

void change_linktype_header(const char *read_pcap_path, const char *save_pcap_path, unsigned int write_linktype){
    double d[READ_BUF];
    std::ifstream ifout(read_pcap_path, std::ios::binary);
    std::ofstream ofout(save_pcap_path, std::ios::binary);
    if(!ifout){
        std::cout << "ifout open error";
        exit(EXIT_FAILURE);
    }
        if(!ofout){
        std::cout << "ofout open error";
        exit(EXIT_FAILURE);
    }
    // get file size
    ifout.seekg(0, std::ios::end);
    long long int size = ifout.tellg();
    ifout.seekg(0);
    // seek header
    for (int i=0;i<SEEK_LINKTYPE;i++){
        ifout.read((char *)&d, sizeof(char));
        ofout.write((char *)&d, sizeof(char));
    }
    //write link type
    ifout.read((char *)&d, sizeof(char)*2);
    ofout.write((char *)&write_linktype, sizeof(char)*2);
    int p = (size-SEEK_LINKTYPE-2)/(8*READ_BUF);
    int q = (size-SEEK_LINKTYPE-2)%(8*READ_BUF);
    //write others
    for (long long int i=0;i<p;i++){
        ifout.read((char *)&d, sizeof(double)*READ_BUF);
        ofout.write((char *)&d, sizeof(double)*READ_BUF);
    }
    for (int i=0;i<q;i++){
        ifout.read((char *)&d, sizeof(char));
        ofout.write((char *)&d, sizeof(char));
    }
    ifout.close();
    ofout.close();

}



sll_v2_t *my_create_sll_v2(const u_char *pkt){
    sll_v2_t *sll_v2 = new sll_v2_t;
    int shift = 0;
    sll_v2->protocol =  *((unsigned int *)pkt);shift+=sizeof(int);
    sll_v2->interface_index = *((unsigned int *)(pkt+shift));shift+=sizeof(int);
    sll_v2->link_layer_addr_type = *((unsigned short *)(pkt+shift));shift+=sizeof(short);
    sll_v2->packet_type = *((unsigned char*)(pkt+shift));shift+=sizeof(char);
    sll_v2->link_layer_addr_len = *((unsigned char *)(pkt+shift));shift+=sizeof(char);
    sll_v2->source = *((unsigned long *)(pkt+shift));
    sll_v2->unused = 0;
    return sll_v2;
}

sll_v1_t *my_create_sll_v1(sll_v2_t *sll_v2){
    sll_v1_t *sll_v1 = new sll_v1_t;
    sll_v1->packet_type = sll_v2->packet_type;
    sll_v1->link_layer_addr_type = sll_v2->link_layer_addr_type;
    sll_v1->link_layer_addr_len = sll_v2->link_layer_addr_len;
    sll_v1->source = sll_v2->source;
    sll_v1->unused = 0;
    sll_v1->protocol =  sll_v2->protocol;
    return sll_v1;
}

void my_write_sll_v1_header(sll_v1_t *sll_v1, u_char *v1_header){
    int shift = 0;
    strncpy(v1_header, sll_v1, sizeof(u_short));
}


int main(int argc, char *argv[]){
    const u_char *pkt;

    u_char *pkt_writen;
    u_char *pkt_sll_v1_header;

    // read pcapfile
    pcap_t *pcap = my_pcap_read(argv[1]);

    //create dumper
    pcap_dumper_t *dumper = my_create_pcap_dumper(argv[2]);

    struct pcap_pkthdr pkthdr;
    bool f = true;
    while ((pkt = pcap_next(pcap, &pkthdr))) {
        if(f){
            pkt_writen = new u_char[(pkthdr.len)-SLL_V2_LEN+SLL_V1_LEN];
            pkt_sll_v1_header = new u_char[SLL_V1_LEN];
            sll_v2_t *sll_v2 = my_create_sll_v2(pkt);
            sll_v1_t *sll_v1 = my_create_sll_v1(sll_v2);

            //strncpy(pkt_writen, pkt_sll_v1_header,SLL_V1_LEN);
            //strncpy(pkt_writen+SLL_V1_LEN, pkt+SLL_V2_LEN, (pkthdr.len)-SLL_V2_LEN+SLL_V1_LEN);
            f = false;
            //std::cout << "protocol : 0x" << std::hex << sll_v2->protocol << "\n";
            //std::cout << "interface_index : 0x" << std::hex << sll_v2->interface_index << "\n";
            //std::cout << "link_layer_addr_type : 0x" << std::hex << sll_v2->link_layer_addr_type << "\n";
            //std::cout << "packet_type : 0x" << std::hex << (int)sll_v2->packet_type << "\n";
            //std::cout << "link_layer_addr_len : 0x" << std::hex << (int)sll_v2->link_layer_addr_len << "\n";
            //std::cout << "source :: " << std::hex << sll_v2->source << "\n";
            //std::cout << "unused : 0x" << std::hex << sll_v2->unused << "\n";
            std::cout << "packet_type : 0x" << std::hex << sll_v1->packet_type << "\n";
            std::cout << "link_layer_addr_type : 0x" << std::hex << sll_v1->link_layer_addr_type << "\n";
            std::cout << "link_layer_addr_len : 0x" << std::hex << sll_v1->link_layer_addr_len << "\n";
            std::cout << "source : 0x" << std::hex << sll_v1->source << "\n";
            std::cout << "unused : 0x" << std::hex << sll_v1->unused << "\n";
            std::cout << "protocol : 0x" << std::hex << sll_v1->protocol << "\n";
        }   
        pcap_dump((u_char *)dumper, &pkthdr, pkt);
    }
    pcap_dump_flush(dumper);
    pcap_dump_close(dumper);
    pcap_close(pcap);
    

    // change pcap header link type
    change_linktype_header(argv[2], argv[3], 0x0114);

    return 0;

}
