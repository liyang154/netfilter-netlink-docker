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
#include <linux/netfilter_ipv4.h>//ip_route_me_harder
#include <linux/mm.h>
#include <net/ip.h>
struct dst_entry *output_dst = NULL; //出口设备指针
////aaabbbccchhhiii
unsigned int my_hookout(unsigned int hooknum,struct sk_buff *skb,
                        const struct net_device *in,
                        const struct net_device *out,
                        int (*okfn)(struct sk_buff *))
{
    //ip_local_out(skb_cp);
    struct iphdr *iph = ip_hdr(skb);
    struct tcphdr *tcph = tcp_hdr(skb);
    struct udphdr *udph = udp_hdr(skb);
    unsigned int   ip_hdr_off;
    unsigned int ntcp_hdr_off;
    if(iph->saddr==in_aton("172.17.0.2"))
    {
        if(likely(iph->protocol==IPPROTO_UDP))
        {
            printk("request UDP\n");
            return NF_ACCEPT;
        }
        if(likely(iph->protocol==IPPROTO_ICMP))
        {
            printk("ICMP\n");
            printk(KERN_INFO"source IP is %pI4\n", &iph->saddr);
            printk(KERN_INFO"dest IP is %pI4\n", &iph->daddr);
            //iph->saddr=in_aton("192.168.0.101");
            iph->saddr=in_aton("172.17.0.3");
            iph->check=0;
            iph->check=ip_fast_csum((unsigned char*)iph, iph->ihl);
            //ip_route_me_harder(skb, RTN_UNSPEC);
            return NF_ACCEPT;
        }
        printk("request tcp\n");
        printk(KERN_INFO"source IP is %pI4\n", &iph->saddr);
        printk(KERN_INFO"dest IP is %pI4\n", &iph->daddr);
        //iph->saddr=in_aton("192.168.0.101");
        iph->saddr=in_aton("172.17.0.3");
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
    printk(KERN_INFO"aaaaaresponse source IP is %pI4\n", &iph->saddr);
    printk(KERN_INFO"aaaaadest IP is %pI4\n", &iph->daddr);
    if(iph->daddr==in_aton("172.17.0.3"))
    //if(iph->daddr==in_aton("192.168.0.101"))
    {
        if(likely(iph->protocol==IPPROTO_UDP))
        {
            printk("Response UDP\n");
            return NF_ACCEPT;
        }
        if(likely(iph->protocol==IPPROTO_ICMP))
        {
            printk("response ICMP\n");
            printk(KERN_INFO"response source IP is %pI4\n", &iph->saddr);
            printk(KERN_INFO"dest IP is %pI4\n", &iph->daddr);
            //iph->saddr=in_aton("218.7.43.8");
            iph->daddr=in_aton("172.17.0.2");
            iph->check=0;
            iph->check=ip_fast_csum((unsigned char*)iph, iph->ihl);
            //路由查找
           /* if(ip_route_me_harder(skb, RTN_UNSPEC)){
               // kfree_skb(skb_cp);
                printk("ip route failed \r\n");
                return NF_ACCEPT;
            }*/
            /*struct dst_entry * dst=skb_dst(skb);
            //dst_hold(dst);
            if(dst==NULL)
            {
                printk("error to find dst\n");
            }*/
            //dst_release(dst);
            //dst=NULL;
            //skb->_skb_refdst = NULL;
            //dst_release(skb->_skb_refdst);
            return NF_ACCEPT;
        }
        printk(KERN_INFO"source IP is %pI4\n", &iph->saddr);
        printk(KERN_INFO"dest IP is %pI4\n", &iph->daddr);
        //iph->saddr=in_aton("218.7.43.8");
        iph->daddr=in_aton("172.17.0.2");
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
    }
    return NF_ACCEPT;
}
unsigned int my_hookin1(unsigned int hooknum,struct sk_buff *skb,
                       const struct net_device *in,
                       const struct net_device *out,
                       int (*okfn)(struct sk_buff *))
{
    struct iphdr *iph = ip_hdr(skb);
    if(iph->protocol==IPPROTO_ICMP)
    {
        printk(KERN_INFO"forward source IP is %pI4\n", &iph->saddr);
        printk(KERN_INFO"forward dest IP is %pI4\n", &iph->daddr);
    }
    return NF_ACCEPT;
}
static struct nf_hook_ops nh_out = {
        .hook = my_hookout,
        .pf = PF_INET,
        .hooknum = NF_INET_POST_ROUTING,
        //.priority = NF_IP_PRI_FIRST,
        .priority = NF_IP_PRI_NAT_SRC,
        .owner = THIS_MODULE,
};

static struct nf_hook_ops nh_in = {
        .hook = my_hookin,
        .pf = PF_INET,
        .hooknum = NF_INET_PRE_ROUTING,
        //.priority = NF_IP_PRI_FIRST,
        .priority = NF_IP_PRI_NAT_DST,
        .owner = THIS_MODULE,
};
static struct nf_hook_ops nh_in_1 = {
        .hook = my_hookin1,
        .pf = PF_INET,
        .hooknum =NF_INET_FORWARD,
        .priority = NF_IP_PRI_FIRST,
        //.priority = NF_IP_PRI_NAT_DST,
        .owner = THIS_MODULE,
};
static int __init http_init(void)
{
    //注册钩子函数
    nf_register_hook(&nh_in);
    nf_register_hook(&nh_in_1);
    nf_register_hook(&nh_out);
    printk("register getRoutingInfo mod\n");
    printk("Start...\n");
    return 0;
}

static void __exit http_exit(void)
{
    nf_unregister_hook(&nh_in);
    nf_unregister_hook(&nh_in_1);
    nf_unregister_hook(&nh_out);
    printk(KERN_INFO"removed\n");
}

module_init(http_init);
module_exit(http_exit);
MODULE_LICENSE("GPL");
