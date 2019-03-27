#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <stddef.h>
#include <endian.h>

#include "lib/api.h"
#include "lib/ipv6.h"
#include "lib/bpf_endian.h"

// static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) =
// 	(void *) BPF_FUNC_trace_printk;

// #define trace_printk(fmt, ...) do { \
// 	char _fmt[] = fmt; \
// 	bpf_trace_printk(_fmt, sizeof(_fmt), ##__VA_ARGS__); \
// 	} while (0)

// SEC("classifier")
// int cls_main(struct __sk_buff *skb)
// {
// 	return -1;
// }

SEC("ingress")
int pingpong(struct __sk_buff *skb)
{
	/* We will access all data through pointers to structs */
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	/* first we check that the packet has enough data,
	 * so we can access the three different headers of ethernet, ip and icmp
	 */
	if (data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) > data_end)
	{
		bpf_printk("NOT IPV6 PACKET\n");

		return TC_ACT_UNSPEC;
	}

	/* for easy access we re-use the Kernel's struct definitions */
	// struct ethhdr  *eth  = data;
	struct ipv6hdr *ip = (data + ETH_HLEN);

	/* Only actual IP packets are allowed */
	// if (eth->h_proto != __constant_htons(ETH_P_IP))
	// 	return TC_ACT_UNSPEC;

	if (ip->version != IP6VERSION)
	{
		// bpf_printk("PASS PACKET %d %d %x\n", ip->version, IP6VERSION, *start);
		return TC_ACT_UNSPEC;
	}
	bpf_printk("GOT IPv6 Packet: %x %d\n", skb->protocol, ip->nexthdr);


	union v6addr tg_sip;
	tg_sip.addr16[0] = bpf_htons(0x2019);
	tg_sip.addr16[7] = bpf_htons(0x200);

	// union v6addr sip;
	// if (ipv6_load_saddr(skb, ETH_HLEN, &sip) < 0)
	// {
	// 	bpf_printk("Load Failed\n");
	// 	return TC_ACT_UNSPEC;
	// }


	// int eq = ipv6_addrcmp(&tg_sip, &sip);
	// bpf_printk("GOT IPv6 Packet FORM SOURCE %llx %llx\n", bpf_ntoh64(sip.x1), bpf_ntoh64(sip.x2));
	// bpf_printk("EQUAL %d\n", eq);

	// if (eq < 0) {
	// 	return TC_ACT_UNSPEC;
	// }
	// __be16 from_proto = skb->protocol;
	// __be16 to_proto = bpf_htons(ETH_P_IP);
	// int en = (from_proto == bpf_htons(ETH_P_IPV6) &&
	//       to_proto == bpf_htons(ETH_P_IP));
	int en = skb_change_proto(skb, bpf_htons(ETH_P_IP), 0);
	if (en < 0) {
		bpf_printk("FUCK3 %d %x\n", en, skb->protocol);
		return TC_ACT_UNSPEC;
	}

	bpf_printk("FUCK2\n");

	// ipv6_load_saddr(skb, ETH_HLEN, &dip);

	// bpf_printk("GOT IPv6 Packet FORM SOURCE %04x ", bpf_ntohl(sip.p1));
	// bpf_printk("%x %x\n", bpf_ntohl(sip.p3), bpf_ntohl(sip.p4));

	// union v6addr _saddr = {{0x2002ac12, 0xfecf0001, 0x0, 0x26}} ;

	// union v6addr *saddr = (union v6addr *) &ip->saddr;
	// /* We handle only ICMP traffic */
	// 	trace_printk("GOT IPv6 Packet FORM SOURCE %x %x ", saddr->p1, saddr->p2);
	// 	trace_printk("%x %x\n", saddr->p3, saddr->p4);
	// if (ipv6_addrcmp(saddr, &_saddr)) {

	// }

	return TC_ACT_UNSPEC;
}

char __license[] SEC("license") = "GPL";