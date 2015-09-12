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
#include<netinet/ip.h>
#include<netinet/tcp.h>
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

flow_map_t flows[flowhash];

int main(int argc, char **argv)
{
    parse_args(argc, argv);

    int sock_raw = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
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
    int count = 0;
    while(true)
    {
        struct sockaddr saddr;
        int saddr_size = sizeof(saddr);
        char buffer[2000];
        int sz = recvfrom(sock_raw , buffer , sizeof(buffer) , 0 , &saddr , (socklen_t*)&saddr_size);
        if(sz <0 )
        {
            std::cerr << "Error recv packet: " << strerror(errno) << "(" << errno << ")";
            return 1;
        }
        struct iphdr *iph = (struct iphdr*)buffer;

        struct tcphdr *tcph=(struct tcphdr*)(buffer + iph->ihl*4);
        parse_data(buffer + iph->ihl*4 + tcph->doff*4, sz - (iph->ihl*4 + tcph->doff*4));
    }
    close(sock_raw);

    return 0;
}

int parse_data(char* data, unsigned len)
{
    //TODO: insert into flows
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
