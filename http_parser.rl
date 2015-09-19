/**
      HTTP parser for packet sniffer
      Author: Ilya Gavrilov <gilyav@gmail.com>
*/

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <string>
#include <iostream>
#include <list>
#include "http.h"


//output format:
//"%request.timestamp %source.ip %dest.ip  %request.header.host %request.line  %response.protocol %response.size %response.code
void end_msg(bool cli, http_state_t *state)
{
    if(cli)
        state->end_message(state->host + " " + state->req_line);
    else
        state->end_message(" " + state->protocol + " " + state->content_len_str + " " + state->code + " -");
}

%%{
    machine http_srv;
    include http "./http.rl";

    main :=  (http_response >reset_http @end_http_headers)+ ;
}%%

%% write data;

void http_state_t::init_srv(http_state_t::callback f)
{
    end_message = f;
	%% write init;
}

int http_state_t::parse_srv(const char *data, int length, int isEof)
{
	const char *p = data;
	const char *pe = data + length;
	const char *eof = isEof ? pe : 0;
    bool cli = false;

	%% write exec;

    len += length;
    if ( cs == http_srv_error )
        return -1;
    return 0;
}

void http_state_t::add(std::string& str, char *data)
{
    if( str.length() + strlen(data) > MAX_REQ_LEN )
        return;
    str.append(data);
}

void http_state_t::add(std::string& str, char ch)
{
    if( str.length() + 1 > MAX_REQ_LEN )
        return;
    str.append(1,ch);
}

%%{
	machine http_cli;

    include http "./http.rl";

	main :=  (http_request >reset_http @end_http_headers)+;

}%%

%% write data;

void http_state_t::init_cli(http_state_t::callback f)
{
    end_message = f;
	%% write init;
}

int http_state_t::parse_cli(const char *data, int length, int isEof)
{
	const char *p = data;
	const char *pe = data + length;
	const char *eof = isEof ? pe : 0;
    bool cli = true;

	%% write exec;

    len += length;
    if ( cs == http_cli_error )
        return -1;
    return 0;
}

#ifdef TEST
int main(int argc, char **argv)
{
    if(argc<3)
    {
        printf("No enough parameter given\n");
        return -1;
    }
    FILE *fcli = fopen(argv[1],"r");
    if(!fcli)
    {
        printf("Error open file %s\n", argv[1]);
        return -1;
    }
    FILE *fsrv = fopen(argv[2],"r");
    if(!fsrv)
    {
        printf("Error open file %s\n", argv[2]);
        return -1;
    }

    std::list<std::string> reqs;
    auto got_cli = [&reqs](std::string str)
    {
        reqs.push_back(str);
    };

    auto got_srv = [&reqs](std::string str)
    {
        if(reqs.empty())
        {
            std::cout << "Error: no requests!" << std::endl;
            return;
        }
        std::cout << reqs.front() << " " << str << std::endl;
        reqs.pop_front();
    };

    char buf[1];

    http_state_t state_cli;
    state_cli.init_cli(got_cli);
    int res = 0;
    while(!res && !feof(fcli))
    {
        int rd = fread(buf,1,sizeof(buf),fcli);
        if(!rd)break;
        res = state_cli.parse_cli(buf, rd, 0);
        if(res<0)
            std::cout << "Error parse cli side" << std::endl;
    }

    http_state_t state_srv;
    state_srv.init_srv(got_srv);
    res = 0;
    while(!res && !feof(fsrv))
    {
        int rd = fread(buf,1,sizeof(buf),fsrv);
        if(!rd)break;
        res = state_srv.parse_srv(buf, rd, 0);
        if(res<0)
            std::cout << "Error parse srv side" << std::endl;
    }

    fclose(fcli);
    fclose(fsrv);

    return 0;
}
#endif
