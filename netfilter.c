#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Abilbekov Ilyas, Akhmed Alibek, Dastan Tlesh, Nurbergen Zholay, Nurtazinov Islam");
MODULE_DESCRIPTION("Linux kernel module that intercepts incoming IPv4 TCP packets and drops them if they contain a specific secret sequence in their payload");


static const char* SECRET_SEQUENCE = "32456789k0l3456789shsadb";

static struct nf_hook_ops nf_hook_ops_struct = {
    .hook = nf_hook_func,
    .pf = PF_INET,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST,
};

static unsigned int nf_hook_func(void* priv, struct sk_buff* skb, const struct nf_hook_state* state)
{
    if (skb->protocol != htons(ETH_P_IP)) {
        return NF_ACCEPT;
    }

    struct iphdr* ip_header = ip_hdr(skb);

    if (ip_header->protocol == IPPROTO_TCP) {
        struct tcphdr* tcp_header = tcp_hdr(skb);

        char* payload = (char*)(tcp_header + 1);

        int payload_len = ntohs(ip_header->tot_len) - sizeof(struct iphdr) - sizeof(struct tcphdr);

        char* found = strstr(payload, SECRET_SEQUENCE);
        if (found != NULL) {
            printk(KERN_INFO "Dropping packet containing secret sequence: %s\n", SECRET_SEQUENCE);
            return NF_DROP;
        }
    }

    return NF_ACCEPT;
}

static int __init module_init_func(void)
{
    printk(KERN_INFO "Initializing module\n");
    nf_register_hook(&nf_hook_ops_struct);

    return 0;
}

static void __exit module_cleanup_func(void)
{
    printk(KERN_INFO "Cleaning up module\n");
    nf_unregister_hook(&nf_hook_ops_struct);
}

module_init(module_init_func);
module_exit(module_cleanup_func);

