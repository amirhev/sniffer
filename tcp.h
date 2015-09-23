//#define TCP_DEBUG(x...) {printf(x);fflush(stdout);}
#define TCP_DEBUG(x...) {}

struct tcp_segment_t
{
    uint32_t seq;
    std::string data;

    tcp_segment_t(uint32_t s, char *d, uint32_t l): seq(s)
    {
        data.assign(d,l);
    }

    bool add(uint32_t s, char *d, uint32_t l)
    {
        TCP_DEBUG("%s: seq: %u new_seq: %u l: %u\n",__PRETTY_FUNCTION__, seq, s, l);
        data.resize( s - seq );
        data.append(d,l);
        return true;
    }
};

struct cache_data_t
{
    uint32_t syn_seq;
    bool got_syn;
    typedef std::list<tcp_segment_t> segments_t;
    segments_t segments;
    segments_t::iterator seg_it;

    cache_data_t(): got_syn(false) 
    {
        seg_it = segments.end();
    }
    void syn(uint32_t seq) {syn_seq = seq; got_syn = true;}
    bool put(uint32_t seq, char *data, unsigned len)
    {
        TCP_DEBUG("%s: seq: %u len: %u seg_end: %d empty: %d\n",__PRETTY_FUNCTION__, seq, len, seg_it==segments.end(), segments.begin() == segments.end());
        if( segments.begin() == segments.end() )
        {
            TCP_DEBUG("%s: first segment\n",__PRETTY_FUNCTION__);
            segments.push_back(tcp_segment_t(seq,data,len));
            seg_it = segments.begin();
            return true;
        }

        while ( seq > seg_it->seq + seg_it->data.length() )
        {
            TCP_DEBUG("%s: after segment %u\n",__PRETTY_FUNCTION__, seg_it->seq);
            if( ++seg_it == segments.end() )
            {
                segments.push_back(tcp_segment_t(seq,data,len));
                seg_it = segments.end();
                seg_it--;
            TCP_DEBUG("%s: after segment insert after seq: %u\n",__PRETTY_FUNCTION__, seg_it->seq);
                return true;
            }
        }

        while ( seq < seg_it->seq + seg_it->data.length() )
        {
            TCP_DEBUG("%s: before segment %u\n",__PRETTY_FUNCTION__, seg_it->seq);
            if( seg_it-- == segments.begin() )
            {
                segments.push_front(tcp_segment_t(seq,data,len));
                seg_it = segments.begin();
                return true;
            }
        }

        if( seq >= seg_it->seq && seq <= seg_it->seq + seg_it->data.length() )
        {
            TCP_DEBUG("%s: inside segment %u\n",__PRETTY_FUNCTION__, seg_it->seq);
            return seg_it->add(seq, data, len);
        }

        return false;
    }

    std::string get()
    {
        std::string ret;
        if( segments.begin() == segments.end() )
            return ret;

        segments_t::iterator it = segments.begin();
        if( !got_syn || syn_seq == it->seq )
        {
            ret = it->data;
            TCP_DEBUG("%s: got_syn: %d syn_seq: %u it_seq: %u ret: %lu\n",__PRETTY_FUNCTION__, got_syn, syn_seq, it->seq, ret.length());
            if(seg_it == it && ++seg_it == segments.end())
                seg_it = segments.begin();
            segments.erase(it);
            if(!got_syn)
                syn_seq = it->seq;
            syn_seq += it->data.length();
            got_syn = true;
        }

        return ret;
    }
};

class tcp_cache_t
{
    cache_data_t cache[2];

public:
    bool put(tcphdr *tcph, unsigned tcplen, uint8_t side)
    {
        if(tcph->syn)
            cache[side].syn(ntohl(tcph->seq)+1);

        char *data = (char*)tcph + tcph->doff*4;
        unsigned len = tcplen - tcph->doff*4;

        TCP_DEBUG("%s: side: %u tcplen: %u len: %u seq: %u\n",__PRETTY_FUNCTION__, side, tcplen, len, ntohl(tcph->seq));
        if(len)
            cache[side].put(ntohl(tcph->seq), data, len);

        return true;
    }

    std::string get(uint8_t side)
    {
        return cache[side].get();
    }
};
