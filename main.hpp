#define SEEK_LINKTYPE 20
#define READ_BUF 10
#define SLL_V1_LEN 16
#define SLL_V2_LEN 20

typedef struct sll_v1 sll_v1_t;
typedef struct sll_v2 sll_v2_t;

int check_link_type(pcap_t *pcap);
pcap_t *my_pcap_read(const char *read_pcap_path);
pcap_dumper_t *my_create_pcap_dumper(const char *save_pcap_path);
void change_linktype_header(const char *read_pcap_path, const char *save_pcap_path, unsigned int write_linktype);
sll_v2_t *my_create_sll_v2(u_char *pkt);

struct sll_v1{
    unsigned short packet_type;
    unsigned short link_layer_addr_type;
    unsigned short link_layer_addr_len;
    // not right len : normal six bytes
    unsigned long source;
    unsigned short unused;
    unsigned short protocol;
};

struct sll_v2{
    unsigned int protocol;
    unsigned int interface_index;
    unsigned short link_layer_addr_type;
    unsigned char packet_type;
    unsigned char link_layer_addr_len;
    // not right len : normal six bytes
    unsigned long source;
    unsigned short unused;
};



