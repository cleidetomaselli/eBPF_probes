#include <uapi/linux/ip.h>

struct eth_hdr {
    __be64 dst : 48;
    __be64 src : 48;
    __be16 proto;
} __attribute__((packed));

BPF_ARRAY(IPV4_PACKETS_COUNTER, uint64_t,1);
BPF_ARRAY(IPV6_PACKETS_COUNTER, uint64_t,1);

static __always_inline int handle_rx(struct CTXTYPE *ctx, struct pkt_metadata *md) {
	
	//Parsing L2
	void *data = (void *) (long) ctx->data;
    	void *data_end = (void *) (long) ctx->data_end;
	
    	struct eth_hdr *ethernet = data;
    	
	if (data + sizeof(*ethernet) > data_end)
       		return RX_OK;
        
	
	//Checking for IPv4 packets
       	if (ethernet->proto == bpf_htons(ETH_P_IP)){
		unsigned int key_ipv4 = 0;
		uint64_t * ipv4_pckts_counter = IPV4_PACKETS_COUNTER.lookup(&key_ipv4);
        	if (!ipv4_pckts_counter)
            		pcn_log(ctx, LOG_ERR, "Unable to find IPV4_PACKETS_COUNTER map");
        	else
           		*ipv4_pckts_counter+=1;
        }   

	//Checking for IPv6 packets
	if (ethernet->proto == bpf_htons(ETH_P_IPV6)){
		unsigned int key_ipv6 = 0;
		uint64_t * ipv6_pckts_counter = IPV6_PACKETS_COUNTER.lookup(&key_ipv6);
        	if (!ipv6_pckts_counter)
            		pcn_log(ctx, LOG_ERR, "Unable to find IPV6_PACKETS_COUNTER map");
        	else
           		*ipv6_pckts_counter+=1;
        }  	

    pcn_log(ctx, LOG_TRACE, "IPv4 packet counter: %d", *ipv4_pkcts_counter);
    pcn_log(ctx, LOG_TRACE, "IPv6 packet counter: %d", *ipv6_pkcts_counter);
    return RX_OK;
}
