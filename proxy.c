//go:build ignore

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

struct socket_key {
        __u32 src_ip;
        __u32 dst_ip;
        __u32 src_port;
        __u32 dst_port;
};

struct {
        __uint(type, BPF_MAP_TYPE_SOCKHASH);
        __uint(max_entries, 1<<8);
        __type(key, struct socket_key);
        __type(value, __u32);
} sockmap SEC(".maps");

static inline
void extract_socket_key(struct __sk_buff *skb, struct socket_key *key)
{
        key->src_ip = bpf_ntohl(skb->remote_ip4);
        key->dst_ip = bpf_ntohl(skb->local_ip4);
        key->src_port = bpf_ntohl(skb->remote_port);
        key->dst_port = skb->local_port;
}

SEC("sk_skb")
int sk_skb_stream_verdict_prog(struct __sk_buff *skb) {
	int res=0;
	__bpf_printk("skb->remote_ip4 = 0x%x",bpf_ntohl(skb->remote_ip4));
	__bpf_printk("skb->local_ip4 = 0x%x",bpf_ntohl(skb->local_ip4));
	__bpf_printk("skb->remote_port = 0x%x",bpf_ntohl(skb->remote_port));
	__bpf_printk("skb->local_port = 0x%x",skb->local_port);

	struct socket_key key = {};
	extract_socket_key(skb, &key);

		// doesn't work
		// works
		// res = bpf_sk_redirect_map(skb, &sockmap, 0, 0);
	res = bpf_sk_redirect_hash(skb, &sockmap, &key,0); 
	__bpf_printk("res=%d\n",res);
	return res;

}

char _license[] SEC("license") = "GPL";