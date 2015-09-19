#include <functional>
struct http_state_t {
    static const int MAX_REQ_LEN = 1024;

    int cs;
    int len;
    int top;
    int stack[2];
    int data_len;
    int data_read_len;

    int content_len;
    int content_start;
    uint8_t chunked;

    std::string req_line;
    std::string host;
    std::string protocol;
    std::string code;
    std::string content_len_str;

    void clear()
    {
        content_len = 0;
        content_start = 0;
        chunked = 0;

        req_line.clear();
        host.clear();
        protocol.clear();
        code.clear();
    }

    void add(std::string& str, char ch);
    void add(std::string& str, char *data);

    typedef std::function<void(std::string)> callback;
    callback end_message;

    void init_srv(callback f);
    int parse_srv(const char *data, int length, int isEof);

    void init_cli(callback f);
    int parse_cli(const char *data, int length, int isEof);

};

