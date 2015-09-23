struct pcap_file_hdr_t
{
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

struct pcap_hdr_t
{
    uint32_t sec;
    uint32_t usec;
    uint32_t caplen;
    uint32_t len;
};
