/**
      HTTP packet sniffer and parser main file
      Author: Ilya Gavrilov <gilyav@gmail.com>
*/
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string>
#include <vector>
#include <sstream>
#include <iostream>
#include <algorithm>
#include "sniffer.h"
#include "pcap.h"

std::string interface;
std::string pcapfile;
int streams = 65536;
std::vector<uint16_t> ports;

flow_map_t flows[hashsize];

uint64_t flows_inserts = 0;
uint64_t flows_removes = 0;

flow_t *curr_flow = NULL;
flow_data_t *curr_flow_data = NULL;

int main(int argc, char **argv)
{
    parse_args(argc, argv);

    if(interface.length())
        process_device();
    else if (pcapfile.length())
        process_file();

    return 0;
}

int process_device()
{
    int sock_raw = socket(AF_PACKET , SOCK_RAW,  htons(ETH_P_ALL));
    if(sock_raw < 0)
    {
        std::cerr << "Error create socket" << std::endl;
        return -1;
    }
    if( setsockopt(sock_raw, SOL_SOCKET, SO_BINDTODEVICE, interface.c_str(), interface.length()) )
    {
        std::cerr << "Error bind on interface " << interface << std::endl;
        return -1;
    }

    while(true)
    {
        struct sockaddr_ll saddr;
        int saddr_size = sizeof(saddr);
        char buffer[2000];
        int sz = recvfrom(sock_raw, buffer, sizeof(buffer), 0, (struct sockaddr*)&saddr , (socklen_t*)&saddr_size);
        if(sz <0 )
        {
            std::cerr << "Error recv packet: " << strerror(errno) << "(" << errno << ")";
            return 1;
        }

        process_packet(buffer, sz);

    }
    close(sock_raw);

    return 0;
}

int process_file()
{
    FILE *pcap = fopen(pcapfile.c_str(), "r");
    if(!pcap)
    {
        std::cerr << "Error open file: " << pcapfile << std::endl;
        return -1;
    }
    pcap_file_hdr_t file_hdr;
    if ( fread(&file_hdr, 1, sizeof(file_hdr), pcap) != sizeof(file_hdr) )
    {
        std::cerr << "Error read filehdr file: " << pcapfile << std::endl;
        return -1;
    }

    while(!feof(pcap))
    {
        char buffer[2000];
        pcap_hdr_t hdr;
        size_t sz = fread(&hdr, 1, sizeof(hdr), pcap); 
        if(sz == 0) break;
        if ( sz != sizeof(hdr) )
        {
            std::cerr << "Error read packethdr size: " << sz << " file: " << pcapfile << std::endl;
            return -1;
        }
        if(hdr.caplen > sizeof(buffer))
        {
            std::cerr << "Error wrong packet size: " << hdr.caplen << " file: " << pcapfile << std::endl;
            return -1;
        }
        if ( fread(buffer, 1, hdr.caplen, pcap) != hdr.caplen )
        {
            std::cerr << "Error read packet file: " << pcapfile << std::endl;
            return -1;
        }

        process_packet(buffer, hdr.caplen);
    }
    fclose(pcap);

    return 0;
}

bool process_packet(char *buffer, unsigned len)
{
    ethhdr *eth = (ethhdr*)buffer;
    if(ntohs(eth->h_proto) != ETH_P_IP)
        return false;

    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(ethhdr));
    if(iph->protocol != IPPROTO_TCP)
        return false;

    struct tcphdr *tcph=(struct tcphdr*)(buffer + sizeof(ethhdr) + iph->ihl*4);
    if( 
            !ports.empty() &&
            std::find(ports.begin(), ports.end(), ntohs(tcph->source)) == ports.end() &&
            std::find(ports.begin(), ports.end(), ntohs(tcph->dest)) == ports.end()
      )
        return false;
    unsigned tcpl = len - (sizeof(ethhdr) + iph->ihl*4);
    flow_t flow = {iph->saddr, iph->daddr, tcph->source, tcph->dest};
    uint8_t side = normal_flow(flow);
    flow_data_t flow_data;

    const char * data = buffer + sizeof(ethhdr) + iph->ihl*4 + tcph->doff*4;
    unsigned length = len - (sizeof(ethhdr) + iph->ihl*4 + tcph->doff*4);

    if( length == 0 && !tcph->syn && tcph->ack && !tcph->fin && !tcph->rst)
        return false; // do not need empty ack

    unsigned hf = hashflow(flow);
    auto it = flows[hf].emplace(flow,flow_data);
    if(it.second)
    {
        ++flows_inserts;
        //printf("OPEN FLOW (%lu-%lu=%lu)\n",flows_inserts, flows_removes, flows_inserts-flows_removes);
    }
    if(tcph->fin && it.second)
    {
        flows[hf].erase(flow);
        ++flows_removes;
        //printf("CLOSE FLOW (%lu-%lu=%lu)\n",flows_inserts, flows_removes, flows_inserts-flows_removes);
        return false;
    }
    it.first->second.cache.put(tcph, tcpl, side);
    if(tcph->fin || tcph->rst)
    {
        it.first->second.fin[side] = true;
        if(it.first->second.fin[1-side] || tcph->rst) // both fin got
        {
            flows[hf].erase(flow);
            ++flows_removes;
            //printf("CLOSE FLOW (%lu-%lu=%lu)\n",flows_inserts, flows_removes, flows_inserts-flows_removes);
            return false;
        }
    }

    std::string payload = it.first->second.cache.get(side);
    if(payload.length())
    {
        parse_data(payload.c_str(), payload.length(), side, it.first->first, it.first->second);
    }

    return true;
}

int parse_data(const char* data, unsigned len, uint8_t side, flow_t flow, flow_data_t& flow_data)
{
    curr_flow = &flow;
    curr_flow_data = &flow_data;
    if(flow_data.probed && !flow_data.http)
        return 0;

    if(!flow_data.probed)
    {
        flow_data.probed = true;
        if( flow_data.cli.parse_cli(data, len, 0) < 0 )
        {
            flow_data.http = false;
        }
        else
        {
            flow_data.http = true;
            flow_data.cli_side = side;
        }
        return 0;
    }

    if( side == flow_data.cli_side )
    {
        if( flow_data.cli.parse_cli(data, len, 0) < 0 )
        {
            std::cout << "Error parse cli " << std::endl;
            flow_data.http = false;
        }
    }
    else
    {
        if( flow_data.srv.parse_srv(data, len, 0) < 0 )
        {
            std::cout << "Error parse srv " << std::endl;
            flow_data.http = false;
        }
    }

    return 0;
}

void usage(char **argv, const char* message=NULL)
{
    if(message)
        std::cerr << message << std::endl;
    std::cerr << "Usage: " << argv[0] << " -i <interface> -f <pcap file> -s <max-tcp-streams> -h"<< std::endl;
    exit(-1);
}

void parse_args(int argc, char **argv)
{
    int opt;
    while ((opt = getopt(argc,argv,"i:f:s:p:h")) != EOF)
        switch(opt)
        {
            case 'i':
                if(pcapfile.length())
                    usage(argv, "only -i OR -f can be given");
                interface.assign(optarg);
                break;
            case 'f':
                pcapfile.assign(optarg);
                if(interface.length())
                    usage(argv, "only -i OR -f can be given");
                break;
            case 's':
                streams = std::atoi(optarg);
                if(streams <= 0 )
                    usage(argv, "max-tcp-streams must greater than 0");
                break;
            case 'p':
                {
                    std::stringstream ss(optarg);
                    int i;
                    while (ss >> i)
                    {
                        if(i <= 0 )
                            usage(argv, "port must greater than 0");
                        ports.push_back(i);
                        if (ss.peek() == ',')
                            ss.ignore();
                    }
                }
                break;
            default:
                usage(argv);
        }
    if(!interface.length() && !pcapfile.length())
        usage(argv);
}

void got_http_request(std::string req)
{
    curr_flow_data->reqs.push_back(req);
}

void got_http_response(std::string res)
{
    if(curr_flow_data->reqs.empty())
    {
        std::cout << "Error: no requests!" << std::endl;
        return;
    }
    struct in_addr ip;
    ip.s_addr = curr_flow->src;
    std::string addr1 = inet_ntoa(ip);
    ip.s_addr = curr_flow->dst;
    std::string addr2 = inet_ntoa(ip);
    uint8_t cli_side = curr_flow_data->cli_side;
    time_t curr_time;
    struct tm *info;
    time( &curr_time );
    info = localtime( &curr_time );
    char buffer[20];
    strftime(buffer,20,"%m/%d/%y %H:%M:%S", info);

    std::cout << buffer << " " << (cli_side?addr2:addr1) << " " << (cli_side?addr1:addr2);
    std::cout << curr_flow_data->reqs.front() << " " << res << std::endl;
    curr_flow_data->reqs.pop_front();
}

