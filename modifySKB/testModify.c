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
char *sourceIp[16]={
        "172.17.0.1",
        "172.17.0.2",
        "172.17.0.3",
        "172.17.0.4",
        "172.17.0.5",
        "172.17.0.6",
        "172.17.0.7",
        "172.17.0.8",
        "172.17.0.9",
        "172.17.0.10",
        "172.17.0.11",
        "172.17.0.12",
        "172.17.0.13",
        "172.17.0.14",
        "172.17.0.15",
        "172.17.0.16",
};
int destIp[16]={0};
int tcpSourcePort[16]={0};
int udpSourcePort[16]={0};
int icmpId[16]={0};
int icmpSeq[16]={0};
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
    struct icmphdr *icmph = icmp_hdr(skb);
    int i;
    int ipFlag=-1;//check docker ip
    /*if(strcmp(out->name,"ens37")==0&&iph->saddr==in_aton("192.168.0.104"))
    {
        printk(KERN_INFO
        "request ens37 source IP is %pI4\n", &iph->saddr);
        printk(KERN_INFO
        "request ens37 dest IP is %pI4\n", &iph->daddr);
    }*/
    if(strcmp(out->name,"ens37")==0)
    {
        for(i=0;i<16;i++)
        {
            if(iph->saddr==in_aton(sourceIp[i]))
            {
                ipFlag=i;//docker ip
                if(iph->protocol==IPPROTO_TCP)
                {
                    tcpSourcePort[i]=ntohs(tcph->source);//record source port
                }
                if(iph->protocol==IPPROTO_UDP)
                {
                    udpSourcePort[i]=ntohs(udph->source);
                }
                if(iph->protocol==IPPROTO_ICMP)
                {
                    icmpSeq[i]=icmph->un.echo.sequence;
                    icmpId[i]=icmph->un.echo.id;
                }
                destIp[i]=iph->daddr;
                printk("````destIp=%d\n````",destIp[i]);
                break;
            }
        }
        if (ipFlag!=-1) {
            if (likely(iph->protocol == IPPROTO_UDP)) {
                iph->saddr = in_aton("192.168.0.101");
                udph->check = 0;
                iph->check = 0;
                skb->csum = 0;
                skb->csum = csum_partial(skb_transport_header(skb), (ntohs(iph->tot_len) - iph->ihl * 4), 0);
                udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, (ntohs(iph->tot_len) - iph->ihl * 4), IPPROTO_UDP,
                                                skb->csum);
                skb->ip_summed = CHECKSUM_NONE;
                if (0 == udph->check) {
                    udph->check = CSUM_MANGLED_0;
                }
                iph->check = 0;
                iph->check = ip_fast_csum((unsigned char *) iph, iph->ihl);
                printk("request UDP\n");
                return NF_ACCEPT;
            }
            if (likely(iph->protocol == IPPROTO_ICMP)) {
                printk("request ICMP\n");
                printk(KERN_INFO
                "source IP is %pI4\n", &iph->saddr);
                printk(KERN_INFO
                "dest IP is %pI4\n", &iph->daddr);
                iph->saddr = in_aton("192.168.0.101");
                iph->daddr=in_aton("218.7.43.8");
                iph->check = 0;
                iph->check = ip_fast_csum((unsigned char *) iph, iph->ihl);
                ip_route_me_harder(skb, RTN_UNSPEC);
                return NF_ACCEPT;
            }
            printk("request tcp\n");
            printk(KERN_INFO
            "source IP is %pI4\n", &iph->saddr);
            printk(KERN_INFO
            "dest IP is %pI4\n", &iph->daddr);
            iph->saddr = in_aton("192.168.0.101");
            tcph->check = 0;
            iph->check = 0;
            skb->csum = 0;
            skb->csum = csum_partial(skb_transport_header(skb), (ntohs(iph->tot_len) - iph->ihl * 4), 0);
            tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, (ntohs(iph->tot_len) - iph->ihl * 4), IPPROTO_TCP,
                                            skb->csum);
            skb->ip_summed = CHECKSUM_NONE;
            if (0 == tcph->check) {
                tcph->check = CSUM_MANGLED_0;
            }
            iph->check = 0;
            iph->check = ip_fast_csum((unsigned char *) iph, iph->ihl);
        }
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
    struct icmphdr *icmph = icmp_hdr(skb);
    int ipFlag=-1;
    int i;
    /*if(strcmp(in->name,"ens37")==0&&iph->daddr==in_aton("192.168.0.104"))
    {
        printk(KERN_INFO
        "response ens37 source IP is %pI4\n", &iph->saddr);
        printk(KERN_INFO
        "response ens37 dest IP is %pI4\n", &iph->daddr);
    }*/
    if(iph->daddr==in_aton("192.168.0.101")&&strcmp(in->name,"ens37")==0)
    {
        printk(KERN_INFO"source IP is %pI4\n", &iph->saddr);
        printk("`````fin=%d```````\n",tcph->fin);
        for(i=0;i<16;i++)
        {
            if(ntohs(tcph->dest)==tcpSourcePort[i]&&iph->protocol==IPPROTO_TCP)
            {
                ipFlag=i;
                break;
            }
            if(ntohs(udph->dest)==udpSourcePort[i]&&iph->protocol==IPPROTO_UDP)
            {
                ipFlag=i;
                break;
            }
            if(iph->protocol==IPPROTO_ICMP&&icmph->un.echo.id==icmpId[i]&&icmph->un.echo.sequence==icmpSeq[i])
            {
                ipFlag=i;
                break;
            }
        }
        //docker data
        if(ipFlag!=-1)
        {
            if(likely(iph->protocol==IPPROTO_UDP))
            {
                printk("Response UDP\n");
                iph->daddr=in_aton(sourceIp[ipFlag]);
                udph->check = 0;
                iph->check = 0;
                skb->csum = 0;
                skb->csum = csum_partial(skb_transport_header(skb), (ntohs(iph->tot_len) - iph->ihl * 4), 0);
                udph->check = csum_tcpudp_magic(iph->saddr,iph->daddr, (ntohs(iph->tot_len) - iph->ihl * 4), IPPROTO_UDP, skb->csum);
                skb->ip_summed = CHECKSUM_NONE;
                if (0 == udph->check){
                    udph->check = CSUM_MANGLED_0;
                }
                iph->check=0;
                iph->check=ip_fast_csum((unsigned char*)iph, iph->ihl);
                return NF_ACCEPT;
            }
            if(likely(iph->protocol==IPPROTO_ICMP))
            {
                printk("response ICMP\n");
                printk(KERN_INFO"response source IP is %pI4\n", &iph->saddr);
                printk(KERN_INFO"dest IP is %pI4\n", &iph->daddr);
                iph->daddr=in_aton(sourceIp[ipFlag]);
                iph->check=0;
                iph->check=ip_fast_csum((unsigned char*)iph, iph->ihl);
                return NF_ACCEPT;
            }
            printk(KERN_INFO"source IP is %pI4\n", &iph->saddr);
            printk(KERN_INFO"dest IP is %pI4\n", &iph->daddr);
            iph->daddr=in_aton(sourceIp[ipFlag]);
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
    }
    return NF_ACCEPT;
}
unsigned int my_hookin1(unsigned int hooknum,struct sk_buff *skb,
                       const struct net_device *in,
                       const struct net_device *out,
                       int (*okfn)(struct sk_buff *))
{
    struct iphdr *iph = ip_hdr(skb);
    /*if(iph->protocol==IPPROTO_ICMP)
    {
        printk(KERN_INFO"forward source IP is %pI4\n", &iph->saddr);
        printk(KERN_INFO"forward dest IP is %pI4\n", &iph->daddr);
    }*/
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
