/**
      HTTP packet sniffer and parser header file
      Author: Ilya Gavrilov <gilyav@gmail.com>
*/

#include <map>
#include <list>
#include "http.h"
#include "tcp.h"

static const int hashsize = 65536;

struct flow_t
{
    uint32_t src;
    uint32_t dst;
    uint32_t sport;
    uint32_t dport;

    void reverse()
    {
        std::swap(src,dst);
        std::swap(sport,dport);
    }
};

bool operator<(const flow_t& f1, const flow_t& f2)
{
    if(f1.src < f2.src) return true;
    if(f1.dst < f2.dst) return true;
    if(f1.sport < f2.sport) return true;
    if(f1.dport < f2.dport) return true;
    return false;
}

uint8_t normal_flow(flow_t& f)
{
    uint8_t side;
    if(f.src < f.dst)
        side = 0;
    else if(f.src > f.dst)
        side = 1;
    else if(f.sport < f.dport)
        side = 0;
    else side = 1;

    if(side)
        f.reverse();
    return side;
}

unsigned hashflow(flow_t f)
{
    return (f.src+f.dst+f.sport+f.dport)%hashsize;
}

void got_http_request(std::string req);
void got_http_response(std::string res);

struct flow_data_t
{
    bool fin[2]; // fin for sides
    timeval last_time; // last time packet got

    bool probed;
    bool http;
    uint8_t cli_side;

    typedef std::list<std::string> req_list_t;
    req_list_t reqs;
    http_state_t cli;
    http_state_t srv;

    flow_data_t(): probed(false), http(false), cli_side(0)
    {
        fin[0] = fin[1] = false;
        bzero(&last_time, sizeof(last_time));
        cli.init_cli(got_http_request);
        srv.init_srv(got_http_response);
    }
    tcp_cache_t cache;
};

typedef std::map<flow_t,flow_data_t> flow_map_t;

int process_device();
int process_file();
bool process_packet(char *buffer, unsigned len);
int parse_data(const char* data, unsigned len, uint8_t side, flow_t flow, flow_data_t& flow_data);

void parse_args(int argc, char **argv);
