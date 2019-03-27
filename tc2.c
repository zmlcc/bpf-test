#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <stddef.h>

#include "lib/ipv6.h"

// #include "bpf_helpers.h"

#define SEC(NAME) __attribute__((section(NAME), used))

#ifndef BPF_FUNC
#define BPF_FUNC(NAME, ...)              \
	(*NAME)(__VA_ARGS__) = (void *)BPF_FUNC_##NAME
#endif



static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) =
	(void *) BPF_FUNC_trace_printk;


#define trace_printk(fmt, ...) do { \
	char _fmt[] = fmt; \
	bpf_trace_printk(_fmt, sizeof(_fmt), ##__VA_ARGS__); \
	} while (0)


#define IP6VERSION 6

SEC("egress")
int pingpong(struct __sk_buff *skb)
{
	/* We will access all data through pointers to structs */
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	/* first we check that the packet has enough data,
	 * so we can access the three different headers of ethernet, ip and icmp
	 */
	if (data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) > data_end)
	trace_printk("FUCK\n");
		return TC_ACT_UNSPEC;

	/* for easy access we re-use the Kernel's struct definitions */
	struct ethhdr  *eth  = data;
	struct ipv6hdr   *ip   = (data + sizeof(struct ethhdr));


	/* Only actual IP packets are allowed */
	if (eth->h_proto != __constant_htons(ETH_P_IP))
		return TC_ACT_UNSPEC;

	__u32 *start = data;
	// if (ip->version != IP6VERSION) {
		trace_printk("PASS PACKET %d %x\n", ip->version, start);
	// 	return TC_ACT_UNSPEC;
	// }

	union v6addr _saddr = {{0x2002ac12, 0xfecf0001, 0x0, 0x26}} ;

	union v6addr *saddr = (union v6addr *) &ip->saddr;
	/* We handle only ICMP traffic */
		trace_printk("GOT IPv6 Packet FORM SOURCE %x %x ", saddr->p1, saddr->p2);
		trace_printk("%x %x\n", saddr->p3, saddr->p4);
	if (ipv6_addrcmp(saddr, &_saddr)) {

	}
	return TC_ACT_UNSPEC;

	
}

char __license[] SEC("license") = "GPL";