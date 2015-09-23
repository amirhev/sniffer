/**
      HTTP parser for packet sniffer
      Author: Ilya Gavrilov <gilyav@gmail.com>
*/

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <iostream>


%%{
	machine http;

    action reset_http {
        clear();
    }

	action got_method {
	}

	action got_url {
	}

	action got_http_request {
	}

	action got_version {
	}

	action got_http_response {
	}

	action end_http_headers {
        if(chunked != 0) {
            fcall http_chunked_content;
        }
        else if(content_len!=0) {
            content_start = len + (p-data);
            fcall http_content;
        }

        end_msg(cli, this);
	}

	action got_content_length {
        content_len = data_len;
        content_len_str = std::to_string(content_len);
	}

	action got_transfer_encoding_chunked {
        chunked = 1;
	}

	action got_header {
	}

	action got_http_content {
        if(content_start && len+(p-data) - content_start >= content_len)
        {
            end_msg(cli, this);
            fret;
        }
	}

    action clear_digit
    {
        data_len = 0;
        data_read_len = 0;
    }

    action save_digit
    {
        int digit = (*p) - '0';
        data_len = (data_len * 10) + digit;
    }

    action save_xdigit
    {
        data_len = (data_len <<4 ) + (*p>='a'?*p-87:(*p>='A'?*p-55:*p-'0'));
    }

    action got_hex_len
    {
        data_read_len = data_len;
    }

    get_len = ((digit @save_digit)+) >clear_digit;
    get_len_hex = ((xdigit @save_xdigit)+) >clear_digit;
    get_value = ( any when { data_read_len++<data_len } )+ %when {data_read_len>data_len};
    CRLF = "\r"? "\n";

	method = ('GET'i | 'POST'i | 'CONNECT'i | 'HEAD'i | 'DELETE'i | 'LINK'i | 
			  'PUT'i | 'PATCH'i | 'UNLINK'i | 'TRACE'i) %got_method;

	url = ( [^ ]+ ) %got_url;
	http_version =  ('HTTP/'i digit '.' digit) ${add(protocol,*p);}  %got_version;

	header_content_length = ('Content-Length'i) ':' [ \t]* get_len 
		%got_content_length CRLF ;
	header_transfer_encoding = ('Transfer-Encoding'i) ':' [ \t]* 'chunked'i 
		%got_transfer_encoding_chunked CRLF ;
    header_host = ('Host'i) ':' [ \t]* [^\r\n]+ ${add(host,*p);} CRLF;
	header_other = [^\r\n:]+ ':' [^\r\n]+ CRLF %got_header;
    
	header = header_content_length | header_transfer_encoding | header_host | header_other;

	http_request = 
		( (method . [ \t]+ . url . [ \t]+ . http_version) ${add(req_line,*p);} . CRLF . header* . CRLF )
		@got_http_request;

	http_response = 
		( http_version . [ \t]+ . digit {3} ${add(code,*p);} . [^\r\n]* . CRLF . header* . CRLF ) 
		@got_http_response;

	http_content := ( any+ ) @got_http_content;

    action got_chunked_len
    {
        content_len += data_len;
    }
				  
http_chunked_content := ( get_len_hex %got_chunked_len CRLF @got_hex_len (any when {data_read_len-- > 0} )* %when {data_read_len <= 0} CRLF @{if(data_len==0) { content_len_str = std::to_string(content_len); end_msg(cli, this); fret;}} ) +;
            


}%%


