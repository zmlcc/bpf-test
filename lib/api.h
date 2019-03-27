
#ifndef __BPF_API__
#define __BPF_API__


#include <stdint.h>
#include <linux/bpf.h>



#define SEC(NAME) __attribute__((section(NAME), used))

#ifndef BPF_FUNC
#define BPF_FUNC(NAME, ...)              \
	(*NAME)(__VA_ARGS__) = (void *)BPF_FUNC_##NAME
#endif


static void BPF_FUNC(trace_printk, const char *fmt, int fmt_size, ...);

#ifndef bpf_printk
#define bpf_printk(fmt, ...)                                      \
    do {                                                         \
        char ____fmt[] = fmt;                                  \
        trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    } while (0)
#endif


// #define trace_printk(fmt, ...) do { \
// 	char _fmt[] = fmt; \
// 	bpf_trace_printk(_fmt, sizeof(_fmt), ##__VA_ARGS__); \
// 	} while (0)


static int BPF_FUNC(skb_load_bytes, struct __sk_buff *skb, uint32_t off,
		    void *to, uint32_t len);


static int BPF_FUNC(skb_change_proto, struct __sk_buff *skb, uint32_t proto,
		    uint32_t flags);


/* Packet tunnel encap/decap */
static int BPF_FUNC(skb_get_tunnel_key, struct __sk_buff *skb,
		    struct bpf_tunnel_key *to, uint32_t size, uint32_t flags);
static int BPF_FUNC(skb_set_tunnel_key, struct __sk_buff *skb,
		    const struct bpf_tunnel_key *from, uint32_t size,
		    uint32_t flags);

static int BPF_FUNC(skb_get_tunnel_opt, struct __sk_buff *skb,
		    void *to, uint32_t size);
static int BPF_FUNC(skb_set_tunnel_opt, struct __sk_buff *skb,
		    const void *from, uint32_t size);

#endif