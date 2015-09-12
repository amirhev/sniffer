#include <map>
/**
      HTTP packet sniffer and parser header file
      Author: Ilya Gavrilov <gilyav@gmail.com>
*/

static const int flowhash = 65536;

struct flow_t
{
    uint32_t src;
    uint32_t dst;
    uint32_t sport;
    uint32_t dport;
};

struct flow_data_t
{
};

typedef std::map<flow_t,flow_data_t> flow_map_t;

int parse_data(char* data, unsigned len);

void parse_args(int argc, char **argv);
