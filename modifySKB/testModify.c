#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/init.h>
#include <linux/inet.h>///in_aton()function
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/kmod.h>
#include <linux/workqueue.h>
#include <uapi/linux/netfilter_ipv4.h>
#include <linux/mm.h>
#include <net/ip.h>
////aaaaaaaa
unsigned int tcp_v4_check(int len, u_int32_t saddr, u_int32_t daddr, int num)
{
    return csum_tcpudp_magic(saddr,daddr,len, IPPROTO_TCP,0); ;
}
unsigned int my_hookout(unsigned int hooknum,struct sk_buff *skb,
                        const struct net_device *in,
                        const struct net_device *out,
                        int (*okfn)(struct sk_buff *))
{
    struct sk_buff *skb_cp  = NULL;
    skb_cp = skb_copy(skb, GFP_ATOMIC);
    if(!skb_cp){
        printk(" copy skb fail \r\n");
        return  NF_ACCEPT;
    }
    //ip_local_out(skb_cp);
    struct iphdr *iph = ip_hdr(skb);
    struct tcphdr *tcph = tcp_hdr(skb);
    struct udphdr *udph = udp_hdr(skb);
    unsigned int   ip_hdr_off;
    unsigned int ntcp_hdr_off;
    if(likely(iph->protocol==IPPROTO_UDP))
    {
        printk("requestceshi UDP\n");
       /* udph->check = 0;
        iph->check = 0;
        skb->csum = 0;
        skb->csum = csum_partial(skb_transport_header(skb), (ntohs(iph->tot_len) - iph->ihl * 4), 0);
        udph->check = csum_tcpudp_magic(iph->saddr,iph->daddr, (ntohs(iph->tot_len) - iph->ihl * 4), IPPROTO_UDP, skb->csum);
        //skb->ip_summed = CHECKSUM_NONE;
        skb->ip_summed = CHECKSUM_PARTIAL;*/
        return NF_ACCEPT;
    }
    if(likely(iph->protocol==IPPROTO_ICMP))
    {
        printk("ICMP\n");
        return NF_ACCEPT;
    }
    if(iph->saddr==in_aton("172.17.0.2"))
    {
        printk("request\n");
        printk(KERN_INFO"source IP is %pI4\n", &iph->saddr);
        printk(KERN_INFO"dest IP is %pI4\n", &iph->daddr);
        iph->daddr=in_aton("218.7.43.8");
        ip_hdr_off = iph->ihl << 2;
        ntcp_hdr_off = tcph->doff << 2;


        tcph->check = 0;
        iph->check = 0;
        skb->csum = 0;
        skb->csum = csum_partial(skb_transport_header(skb), (ntohs(iph->tot_len) - iph->ihl * 4), 0);
        tcph->check = csum_tcpudp_magic(iph->saddr,iph->daddr, (ntohs(iph->tot_len) - iph->ihl * 4), IPPROTO_TCP, skb->csum);
        skb->ip_summed = CHECKSUM_NONE;
        if (0 == tcph->check){
            tcph->check = CSUM_MANGLED_0;
        }



        iph->check=0;
        iph->check=ip_fast_csum((unsigned char*)iph, iph->ihl);
       // printk("begin tcp=%d\n",tcph->check);
        /*tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, (ntohs(iph->tot_len) - iph->ihl * 4),
                                        IPPROTO_TCP,
                                        csum_partial(tcph, (ntohs(iph->tot_len) - iph->ihl * 4), 0));
        skb->csum = offsetof(
        struct tcphdr,check);*/

        //printk("end tcp=%d\n",tcph->check);
        //skb->ip_summed = CHECKSUM_PARTIAL;
    }
    return NF_ACCEPT;
}
unsigned int my_hookin(unsigned int hooknum,struct sk_buff *skb,
                       const struct net_device *in,
                       const struct net_device *out,
                       int (*okfn)(struct sk_buff *))
{
    struct iphdr *iph = ip_hdr(skb);
    struct tcphdr *tcph = tcp_hdr(skb);
    struct udphdr *udph = udp_hdr(skb);
    if(likely(iph->protocol==IPPROTO_UDP))
    {
        printk("Response UDP\n");
        /*udph->check = 0;
        iph->check = 0;
        skb->csum = 0;
        skb->csum = csum_partial(skb_transport_header(skb), (ntohs(iph->tot_len) - iph->ihl * 4), 0);
        udph->check = csum_tcpudp_magic(iph->saddr,iph->daddr, (ntohs(iph->tot_len) - iph->ihl * 4), IPPROTO_UDP, skb->csum);
        skb->ip_summed = CHECKSUM_NONE;*/
        return NF_ACCEPT;
    }
    if(likely(iph->protocol==IPPROTO_ICMP))
    {
        iph->saddr=in_aton("218.7.43.8");
        iph->check=0;
        iph->check=ip_fast_csum((unsigned char*)iph, iph->ihl);
        return NF_ACCEPT;
    }
    if(iph->daddr==in_aton("172.17.0.2")&&iph->protocol!=IPPROTO_UDP)
    {
        printk("response\n");
        iph->saddr=in_aton("210.30.199.4");
        printk(KERN_INFO"source IP is %pI4\n", &iph->saddr);
        printk(KERN_INFO"dest IP is %pI4\n", &iph->daddr);
        //skb->csum = tcp_v4_check(skb->len - iph->ihl * 4, iph->saddr,
        //                        iph->daddr, 0);
        tcph->check = 0;
        iph->check = 0;
        skb->csum = 0;
        skb->csum = csum_partial(skb_transport_header(skb), (ntohs(iph->tot_len) - iph->ihl * 4), 0);
        tcph->check = csum_tcpudp_magic(iph->saddr,iph->daddr, (ntohs(iph->tot_len) - iph->ihl * 4), IPPROTO_TCP, skb->csum);
        skb->ip_summed = CHECKSUM_NONE;
        if (0 == tcph->check){
            tcph->check = CSUM_MANGLED_0;
        }



        iph->check=0;
        iph->check=ip_fast_csum((unsigned char*)iph, iph->ihl);
       // printk("begin tcp=%d\n",tcph->check);
        /*tcph->check=csum_tcpudp_magic(iph->saddr,iph->daddr,(ntohs(iph ->tot_len)-iph->ihl*4), IPPROTO_TCP,csum_partial(tcph,(ntohs(iph ->tot_len)-iph->ihl*4),0));
        skb->csum = offsetof(struct tcphdr,check);*/
        //printk("end tcp=%d\n",tcph->check);
        //skb->ip_summed = CHECKSUM_NONE;
        //skb->ip_summed = CHECKSUM_PARTIAL;
        if(likely(iph->protocol==IPPROTO_UDP))
        {
            printk("UDP\n");
        }
    }
    return NF_ACCEPT;
}
static struct nf_hook_ops nh_out = {
        .hook = my_hookout,
        .pf = PF_INET,
        .hooknum = NF_INET_LOCAL_OUT,
        .priority = NF_IP_PRI_FIRST,
        .owner = THIS_MODULE,
};
static struct nf_hook_ops nh_in = {
        .hook = my_hookin,
        .pf = PF_INET,
        .hooknum = NF_INET_LOCAL_IN,
        .priority = NF_IP_PRI_FIRST,
        .owner = THIS_MODULE,
};
static int __init http_init(void)
{
    //注册钩子函数
    nf_register_hook(&nh_in);
    nf_register_hook(&nh_out);
    printk("register getRoutingInfo mod\n");
    printk("Start...\n");
    return 0;
}

static void __exit http_exit(void)
{
    nf_unregister_hook(&nh_in);
    nf_unregister_hook(&nh_out);
    printk(KERN_INFO"removed\n");
}

module_init(http_init);
module_exit(http_exit);
MODULE_LICENSE("GPL");
