#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/inet.h>
#include <linux/jiffies.h>
#include <linux/atomic.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("mdang");
MODULE_DESCRIPTION("Simple firewall: block IP + bandwidth rate limit");
MODULE_VERSION("0.4");

/* IP bị chặn và IP bị rate-limit */
static __be32 block_ip;
static __be32 ratelimit_ip;

/* Bandwidth limit (bytes per second) */
static unsigned long rl_bytes_per_sec = 200000;  // ~200 KB/s
static unsigned long rl_window = HZ;

static unsigned long rl_window_start;
static atomic_long_t rl_bytes_count;

static unsigned int fw_hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    long new_bytes;

    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (!iph)
        return NF_ACCEPT;

    /* 1. Chặn toàn bộ gói từ IP */
    if (iph->saddr == block_ip) {
        pr_info("fw_mod: DROP packet from blocked IP %pI4\n", &iph->saddr);
        return NF_DROP;
    }

    /* 2. Bandwidth rate-limit */
    if (iph->saddr == ratelimit_ip) {

        /* Reset nếu sang cửa sổ thời gian mới */
        if (time_after(jiffies, rl_window_start + rl_window)) {
            rl_window_start = jiffies;
            atomic_long_set(&rl_bytes_count, 0);
        }

        /* Tính tổng byte */
        new_bytes = atomic_long_add_return(skb->len, &rl_bytes_count);

        pr_info("fw_mod: bytes=%ld\n", new_bytes);

        if (new_bytes > rl_bytes_per_sec) {
            pr_info("fw_mod: BW limit exceeded — dropping packet\n");
            return NF_DROP;
        }

        return NF_ACCEPT;
    }

    return NF_ACCEPT;
}

/* Netfilter Hook */
static struct nf_hook_ops fw_nfho = {
    .hook     = fw_hook_func,
    .pf       = PF_INET,
    .hooknum  = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST,
};

static int __init fw_module_init(void)
{
    int ret;

    /* IP cần block và IP cần giới hạn băng thông */
    block_ip     = in_aton("192.168.1.102");
    ratelimit_ip = in_aton("192.168.1.103");

    rl_window_start = jiffies;
    atomic_long_set(&rl_bytes_count, 0);

    ret = nf_register_net_hook(&init_net, &fw_nfho);
    if (ret) {
        pr_err("fw_mod: failed to register hook: %d\n", ret);
        return ret;
    }

    pr_info("fw_mod: loaded (IP block + bandwidth limit)\n");
    return 0;
}

static void __exit fw_module_exit(void)
{
    nf_unregister_net_hook(&init_net, &fw_nfho);
    pr_info("fw_mod: unloaded\n");
}

module_init(fw_module_init);
module_exit(fw_module_exit);
