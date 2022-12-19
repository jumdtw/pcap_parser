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
    // a = 0x ab cd ef gh
    unsigned int a = *((unsigned int *)pkt);
    unsigned int b = 0;
    // b = 0x gh 00 00 00
    b = ((a << 8*3)&0xFF000000);
    // b = 0x gh ef 00 00
    b |= ((a << 8*1)&0x00FF0000);
    // b = 0x gh ef cd 00
    b |= ((a >> 8*1)&0x0000FF00);
    // b = 0x gh ef cd ab
    b |= ((a >> 8*3)&0x000000FF);
    sll_v2->protocol =  b;shift+=sizeof(int);

    a = *((unsigned int *)(pkt+shift));
    b = 0;
    b = ((a << 8*3)&0xFF000000);
    b |= ((a << 8*1)&0x00FF0000);
    b |= ((a >> 8*1)&0x0000FF00);
    b |= ((a >> 8*3)&0x000000FF);
    sll_v2->interface_index = b;shift+=sizeof(int);

    // a = 0x ab cd
    unsigned short c = *((unsigned short *)(pkt+shift));
    unsigned short d = 0;
    // d = 0x cd 00
    d = c << 8*1;
    // d = 0x cd ab
    d |= ((c >> 8*1)&0x00FF);
    sll_v2->link_layer_addr_type = c;shift+=sizeof(short);

    sll_v2->packet_type = *((unsigned char*)(pkt+shift));shift+=sizeof(char);
    sll_v2->link_layer_addr_len = *((unsigned char *)(pkt+shift));shift+=sizeof(char);

    // e = 0x ab cd ef gh ij kn ml zz : zz is unused 
    unsigned long e = *((unsigned long *)(pkt+shift));
    unsigned long f = 0;
    // f = 0x ml 00 00 00 00 00 00 00
    f = ((e << 8*6)&0xFF00000000000000);
    // f = 0x ml kn 00 00 00 00 00 00
    f |= ((e << 8*4)&0x00FF000000000000);
    // f = 0x ml kn ij 00 00 00 00 00
    f |= ((e << 8*2)&0x0000FF0000000000);
    // f = 0x ml kn ij gh 00 00 00 00
    f |= ((e)&0x000000FF00000000);
    // f = 0x ml kn ij gh ef 00 00 00
    f |= ((e >> 8*2)&0x00000000FF000000);
    // f = 0x ml kn ij gh ef cd 00 00
    f |= ((e >> 8*4)&0x0000000000FF0000);
    // f = 0x ml kn ij gh ef cd ab 00
    f |= ((e >> 8*6)&0x000000000000FF00);
    // f = 0x ml kn ij gh ef cd ab zz
    f &= (0xFFFFFFFFFFFFFF00);
    sll_v2->source = e;
    return sll_v2;
}

sll_v1_t *my_create_sll_v1(sll_v2_t *sll_v2){
    sll_v1_t *sll_v1 = new sll_v1_t;
    //print_v2_header((u_char *)sll_v2);
    sll_v1->packet_type = (unsigned short)sll_v2->packet_type;
    sll_v1->link_layer_addr_type = sll_v2->link_layer_addr_type;
    sll_v1->link_layer_addr_len = (unsigned short)sll_v2->link_layer_addr_len;
    sll_v1->source = sll_v2->source;
    sll_v1->protocol =  (unsigned short)(sll_v2->protocol>>8*2);
    return sll_v1;
}

void my_edian_disp_to_raw(u_char *dst, sll_v1_t *sll_v1){
    int shift = 0;
    unsigned short a = 0;
    // packet_type
    // a = 0x ab cd
    // a = 0x cd 00
    a = (sll_v1->packet_type) << 8*1;
    // a = 0x cd ab
    a |= (((sll_v1->packet_type) >> 8*1)&0x00FF);
    my_write_raw_data(dst, (u_char *)(&a), sizeof(u_short));shift+=sizeof(u_short);a = 0;
    
    // link_layer_addr_type
    a = (sll_v1->link_layer_addr_type) << 8*1;
    a |= (((sll_v1->link_layer_addr_type) >> 8*1)&0x00FF);
    my_write_raw_data(dst+shift, (u_char *)(&a), sizeof(u_short));shift+=sizeof(u_short);a = 0;
    
    // link_layer_addr_len
    a = (sll_v1->link_layer_addr_len) << 8*1;
    a |= (((sll_v1->link_layer_addr_len) >> 8*1)&0x00FF);
    my_write_raw_data(dst+shift, (u_char *)(&a), sizeof(u_short));shift+=sizeof(u_short);a = 0;
    /*
    // source
    // e = 0x zz zz ef gh ij kn ml op : zz is unused
    unsigned long f = 0;
    // f = 0x op 00 00 00 00 00 00 00
    f = ((sll_v1->source << 8*7)&0xFF00000000000000);

    // f = 0x op ml 00 00 00 00 00 00
    f |= ((sll_v1->source << 8*5)&0x00FF000000000000);

    // f = 0x op ml kn 00 00 00 00 00
    f |= ((sll_v1->source << 8*3)&0x0000FF0000000000);

    // f = 0x op ml kn ij 00 00 00 00
    f |= ((sll_v1->source << 8*1)&0x000000FF00000000);

    // f = 0x op ml kn ij gh 00 00 00
    f |= ((sll_v1->source >> 8*1)&0x00000000FF000000);

    // f = 0x op ml kn ij gh ef 00 00
    f |= ((sll_v1->source >> 8*3)&0x0000000000FF0000);

    // f = 0x op ml kn ij gh ef zz 00
    f &= (0xFFFFFFFFFFFF00FF);

    // f = 0x op ml kn ij gh ef zz zz
    f &= (0xFFFFFFFFFFFFFF00);
    std::cout << "source f: 0x" << std::hex << f << "\n";
    my_write_raw_data(dst+shift, (u_char *)(&f), sizeof(u_long));std::cout << "source dst: 0x" << std::hex << *((u_long *)(dst+shift)) << "\n";shift+=sizeof(u_long);
    */
    my_write_raw_data(dst+shift, (u_char *)(&sll_v1->source), sizeof(u_long));shift+=sizeof(u_long);
    // protocol
    a = (sll_v1->protocol) << 8*1;
    a |= (((sll_v1->protocol) >> 8*1)&0x00FF);
    my_write_raw_data(dst+shift, (u_char *)(&a), sizeof(u_short));
}

void my_write_raw_data(u_char *dst, u_char *src, int len){
    for(int i=0;i<len;i++){
        dst[i] = src[i];
    }
}

void print_v2_header(u_char *pkt_sll_v2_header){
    sll_v2_t *sll_v2 = (sll_v2_t *)pkt_sll_v2_header;
    std::cout << "pkt_sll_v2_header protocol : 0x" << std::hex << sll_v2->protocol << "\n";
    std::cout << "pkt_sll_v2_header interface_index : 0x" << std::hex << sll_v2->interface_index << "\n";
    std::cout << "pkt_sll_v2_header link_layer_addr_type : 0x" << std::hex << sll_v2->link_layer_addr_type << "\n";
    std::cout << "pkt_sll_v2_header packet_type : 0x" << std::hex << (int)sll_v2->packet_type << "\n";    
    std::cout << "pkt_sll_v2_header link_layer_addr_len : 0x" << std::hex << (int)sll_v2->link_layer_addr_len << "\n";
    std::cout << "pkt_sll_v2_header source : 0x" << std::hex << sll_v2->source << "\n";    
}

void print_v1_header(u_char *pkt_sll_v1_header){
    sll_v1_t *sll_v1 = (sll_v1_t *)pkt_sll_v1_header;
    std::cout << "pkt_sll_v1_header packet_type : 0x" << std::hex << sll_v1->packet_type << "\n"; 
    std::cout << "pkt_sll_v1_header link_layer_addr_type : 0x" << std::hex << sll_v1->link_layer_addr_type << "\n"; 
    std::cout << "pkt_sll_v1_header link_layer_addr_len : 0x" << std::hex << sll_v1->link_layer_addr_len << "\n"; 
    std::cout << "pkt_sll_v1_header source : 0x" << std::hex << sll_v1->source << "\n"; 
    std::cout << "pkt_sll_v1_header protocol : 0x" << std::hex << sll_v1->protocol << "\n"; 
}

int main(int argc, char *argv[]){
    const u_char *pkt;
    u_char *buf;
    u_char *pkt_writen;
    u_char *pkt_sll_v1_header;

    // read pcapfile
    pcap_t *pcap = my_pcap_read(argv[1]);

    //create dumper
    pcap_dumper_t *dumper = my_create_pcap_dumper(argv[2]);
    struct pcap_pkthdr pkthdr;
    while ((pkt = pcap_next(pcap, &pkthdr))) {
        pkt_writen = new u_char[(pkthdr.len)-SLL_V2_LEN+SLL_V1_LEN];
        pkt_sll_v1_header = new u_char[SLL_V1_LEN];
        sll_v2_t *sll_v2 = my_create_sll_v2(pkt);
        sll_v1_t *sll_v1 = my_create_sll_v1(sll_v2);

        // display num to little edian
        my_edian_disp_to_raw(pkt_sll_v1_header, sll_v1);
        // pkt_sll_v1_header to pkt_writen
        my_write_raw_data(pkt_writen, pkt_sll_v1_header, SLL_V1_LEN);
        //std::cout << "writen------" << "\n";
        //print_v1_header(pkt_writen);
        // pkt+SLL_V2_LEN to pkt_writen+SLL_V1_HEADER
        my_write_raw_data(pkt_writen+SLL_V1_LEN, (u_char *)pkt+SLL_V2_LEN, (pkthdr.len)-SLL_V2_LEN);

        pkthdr.len = pkthdr.len-SLL_V2_LEN+SLL_V1_LEN;
        pkthdr.caplen = pkthdr.len;
        pcap_dump((u_char *)dumper, &pkthdr, pkt_writen);
        delete pkt_writen;
    }
    pcap_dump_flush(dumper);
    pcap_dump_close(dumper);
    pcap_close(pcap);
    

    // change pcap header link type
    change_linktype_header(argv[2], argv[3], 0x071);

    return 0;

}
