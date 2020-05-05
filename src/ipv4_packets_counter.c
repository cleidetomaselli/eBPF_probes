#include <uapi/linux/ip.h>

struct eth_hdr {
    __be64 dst : 48;
    __be64 src : 48;
    __be16 proto;
} __attribute__((packed));

BPF_ARRAY(IP_PACKETS_COUNTER, uint64_t,1);

static __always_inline int handle_rx(struct CTXTYPE *ctx, struct pkt_metadata *md) {
	
	//Parsing L2
	void *data = (void *) (long) ctx->data;
    	void *data_end = (void *) (long) ctx->data_end;
	
    	struct eth_hdr *ethernet = data;
    	
	if (data + sizeof(*ethernet) > data_end)
       		return RX_OK;
        
	
	//Checking for IPv4 packets
       	if (ethernet->proto == bpf_htons(ETH_P_IP)){
		unsigned int key = 0;
		uint64_t * ip_pckts_counter = IP_PACKETS_COUNTER.lookup(&key);
        	if (!ip_pckts_counter)
            		pcn_log(ctx, LOG_ERR, "Unable to find IP_PACKETS_COUNTER map");
        	else
           		*ip_pckts_counter+=1;
        }    	

    pcn_log(ctx, LOG_TRACE, "IPv4 packet counter: %d", *ip_pkcts_counter);
    return RX_OK;
}
