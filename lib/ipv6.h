
#include <linux/ipv6.h>
#include "bpf_endian.h"

#define IP6VERSION 6

union v6addr {
        struct {
                __u32 p1;
                __u32 p2;
                __u32 p3;
                __u32 p4;
        };
	struct 
	{
		__u64 x1;
		__u64 x2;
	};
	
        __u8 addr[16];
	__u16 addr16[8];
};

// #define GET_V6ADDR(x1, x2, v6addr) \
// __u64 x1 = __builtin_bswap64(*(__u64*)((v6addr).addr)); \
// __u64 x2 = __builtin_bswap64(*(__u64*)((v6addr).addr+8)); \


// static inline void get_v6addr(const union v6addr *ip, __u64 *x1, __u64 *x2) {
// 	*x1 = bpf_ntoh64(*(__u64*)(ip->addr));
// 	*x2 = bpf_ntoh64(*(__u64*)(ip->addr+8));
// }

static inline int ipv6_addrcmp(union v6addr *a, union v6addr *b)
{
	int tmp;

	tmp = a->p1 - b->p1;
	if (!tmp) {
		tmp = a->p2 - b->p2;
		if (!tmp) {
			tmp = a->p3 - b->p3;
			if (!tmp)
				tmp = a->p4 - b->p4;
		}
	}

	return tmp;
}

static inline int ipv6_load_saddr(struct __sk_buff *skb, int off, union v6addr *dst)
{
	return skb_load_bytes(skb, off + offsetof(struct ipv6hdr, saddr), dst->addr,
			      sizeof(((struct ipv6hdr *)NULL)->saddr));
}