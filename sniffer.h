#include <map>
#include <list>
/**
      HTTP packet sniffer and parser header file
      Author: Ilya Gavrilov <gilyav@gmail.com>
*/

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


struct flow_data_t
{
    bool fin[2]; // fin for sides
    timeval last_time; // last time packet got

    bool probed;
    bool http;
    uint8_t cli_side;
    std::list<std::string> reqs;

    flow_data_t(): probed(false), http(false), cli_side(0)
    {
        fin[0] = fin[1] = false;
        bzero(&last_time, sizeof(last_time));
    }
};

typedef std::map<flow_t,flow_data_t> flow_map_t;

int process_device();
int process_file();
int parse_data(const char* data, unsigned len, uint8_t side, flow_data_t& flow_data);

void parse_args(int argc, char **argv);
