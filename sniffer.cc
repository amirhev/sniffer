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
#include "sniffer.h"

std::string interface;
std::string pcapfile;
int streams = 65536;
std::vector<uint16_t> ports;

flow_map_t flows[hashsize];

uint64_t flows_inserts = 0;
uint64_t flows_removes = 0;

flow_data_t *curr_flow = NULL;

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

        ethhdr *eth = (ethhdr*)buffer;
        if(ntohs(eth->h_proto) != ETH_P_IP)
            continue;

        struct iphdr *iph = (struct iphdr*)(buffer + sizeof(ethhdr));
        if(iph->protocol != IPPROTO_TCP)
            continue;

        struct tcphdr *tcph=(struct tcphdr*)(buffer + sizeof(ethhdr) + iph->ihl*4);
        flow_t flow = {iph->saddr, iph->daddr, tcph->source, tcph->dest};
        uint8_t side = normal_flow(flow);
        flow_data_t flow_data;

        const char * data = buffer + sizeof(ethhdr) + iph->ihl*4 + tcph->doff*4;
        unsigned length = sz - (sizeof(ethhdr) + iph->ihl*4 + tcph->doff*4);

        if( length == 0 && tcph->ack && !tcph->fin && !tcph->rst)
            continue; // do not need empty ack

        if( tcph->fin || tcph->rst || length )
        {
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
                continue;
            }
            if(tcph->fin || tcph->rst)
            {
                it.first->second.fin[side] = true;
                if(it.first->second.fin[1-side] || tcph->rst) // both fin got
                {
                    flows[hf].erase(flow);
                    ++flows_removes;
                    //printf("CLOSE FLOW (%lu-%lu=%lu)\n",flows_inserts, flows_removes, flows_inserts-flows_removes);
                    continue;
                }
            }

            if(length)
            {
                parse_data(data, length, side, it.first->second);
            }

        }

    }
    close(sock_raw);

    return 0;
}

int process_file()
{
    return 0;
}

int parse_data(const char* data, unsigned len, uint8_t side, flow_data_t& flow_data)
{
    curr_flow = &flow_data;
    if(flow_data.probed && !flow_data.http)
        return 0;

    if(!flow_data.probed)
    {
        flow_data.probed = true;
        if( flow_data.cli.parse_cli(data, len, 0) < 0 )
        {
            flow_data.http = false;
            return 0;
        }
        else
        {
            flow_data.http = true;
            flow_data.cli_side = side;
        }

    }

    if( side == flow_data.cli_side )
    {
        if( flow_data.cli.parse_cli(data, len, 0) < 0 )
        {
            //std::cout << "Error parse cli " << std::endl;
            flow_data.http = false;
        }
    }
    else
    {
        if( flow_data.srv.parse_srv(data, len, 0) < 0 )
        {
            //std::cout << "Error parse srv " << std::endl;
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
    curr_flow->reqs.push_back(req);
}

void got_http_response(std::string res)
{
    if(curr_flow->reqs.empty())
    {
        std::cout << "Error: no requests!" << std::endl;
        return;
    }
    std::cout << curr_flow->reqs.front() << " " << res << std::endl;
    curr_flow->reqs.pop_front();
}

